<?php defined('SYSPATH') or die('No direct access allowed.');
/**
 * ORM Auth driver.
 *
 * @package    Auth
 * @author     Kohana Team
 * @copyright  (c) 2007-2008 Kohana Team
 * @license    http://kohanaphp.com/license.html
 */
class Kohana_Auth_ORM extends Auth {

	/**
	 * Checks if a session is active.
	 *
	 * @param   mixed    role name string, role ORM object, or array with role names
	 * @return  boolean
	 */
	public function logged_in($role = NULL)
	{
		$status = FALSE;

		// Get the user from the session
		$user = $this->session->get($this->config['session_key']);

		if (is_object($user) AND $user instanceof Model_User AND $user->loaded())
		{
			// Everything is okay so far
			$status = TRUE;

			if ( ! empty($role))
			{
				// Multiple roles to check
				if (is_array($role))
				{
					// Check each role
					foreach ($role as $_role)
					{
						if ( ! is_object($_role))
						{
							$_role = ORM::factory('role', array('name' => $_role));
						}

						// If the user doesn't have the role
						if ( ! $user->has('roles', $_role))
						{
							// Set the status false and get outta here
							$status = FALSE;
							break;
						}
					}
				}
				// Single role to check
				else
				{
					if ( ! is_object($role))
					{
						// Load the role
						$role = ORM::factory('role', array('name' => $role));
					}

					// Check that the user has the given role
					$status = $user->has('roles', $role);
				}
			}
		}

		return $status;
	}

	/**
	 * Logs a user in.
	 *
	 * @param   string   username
	 * @param   string   password
	 * @param   boolean  enable autologin
	 * @return  boolean
	 */
	protected function _login($user, $password, $remember)
	{
		if ( ! is_object($user))
		{
			$username = $user;

			// Load the user
			$user = ORM::factory('user')->where($user->unique_key($username), '=', $username)->find();
		}

		// If the passwords match, perform a login
		if ($user->has('roles', ORM::factory('role', array('name' => 'login'))) AND $user->password === $password)
		{
			if ($remember === TRUE)
			{
				// Create a new autologin token
				$token = ORM::factory('user_token');

				// Set token data
				$token->user_id = $user->id;
				$token->expires = time() + $this->config['lifetime'];
				$token->create();

				// Set the autologin cookie
				Cookie::set('authautologin', $token->token, $this->config['lifetime']);
			}

			// Finish the login
			$this->complete_login($user);

			return TRUE;
		}

		// Login failed
		return FALSE;
	}

	/**
	 * Forces a user to be logged in, without specifying a password.
	 *
	 * @param   mixed    username string, or user ORM object
	 * @return  boolean
	 */
	public function force_login($user)
	{
		if ( ! is_object($user))
		{
			$username = $user;

			// Load the user
			$user = ORM::factory('user');
			$user->where($user->unique_key($username), '=', $username)->find();
		}

		// Mark the session as forced, to prevent users from changing account information
		$this->session->set('auth_forced', TRUE);

		// Run the standard completion
		$this->complete_login($user);
	}

	/**
	 * Logs a user in, based on the authautologin cookie.
	 *
	 * @return  boolean
	 */
	public function auto_login()
	{
		if ($token = Cookie::get('authautologin'))
		{
			// Load the token and user
			$token = ORM::factory('user_token', array('token' => $token));

			if ($token->loaded() AND $token->user->loaded())
			{
				if ($token->user_agent === sha1(Request::$user_agent))
				{
					// Save the token to create a new unique token
					$token->save();

					// Set the new token
					Cookie::set('authautologin', $token->token, $token->expires - time());

					// Complete the login with the found data
					$this->complete_login($token->user);

					// Automatic login was successful
					return TRUE;
				}

				// Token is invalid
				$token->delete();
			}
		}

		return FALSE;
	}

	/**
	 * Log a user out and remove any autologin cookies.
	 *
	 * @param   boolean  completely destroy the session
	 * @param	boolean  remove all tokens for user
	 * @return  boolean
	 */
	public function logout($destroy = FALSE, $logout_all = FALSE)
	{
		// Set by force_login()
		$this->session->delete('auth_forced');

		if ($token = Cookie::get('authautologin'))
		{
			// Delete the autologin cookie to prevent re-login
			Cookie::delete('authautologin');

			// Clear the autologin token from the database
			$token = ORM::factory('user_token', array('token' => $token));

			if ($token->loaded() AND $logout_all)
			{
				ORM::factory('user_token')->where('user_id', '=', $token->user_id)->delete_all();
			}
			elseif ($token->loaded())
			{
				$token->delete();
			}
		}

		return parent::logout($destroy);
	}

	/**
	 * Get the stored password for a username.
	 *
	 * @param   mixed   username string, or user ORM object
	 * @return  string
	 */
	public function password($user)
	{
		if ( ! is_object($user))
		{
			$username = $user;

			// Load the user
			$user = ORM::factory('user');
			$user->where($user->unique_key($username), '=', $username)->find();
		}

		return $user->password;
	}

	/**
	 * Complete the login for a user by incrementing the logins and setting
	 * session data: user_id, username, roles.
	 *
	 * @param   object  user ORM object
	 * @return  void
	 */
	protected function complete_login($user)
	{
		// Update the number of logins
		$user->logins += 1;

		// Set the last login date
		$user->last_login = time();

		// Save the user
		$user->update();

		return parent::complete_login($user);
	}

} // End Auth ORM