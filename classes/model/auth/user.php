<?php defined('SYSPATH') or die('No direct access allowed.');

class Model_Auth_User extends ORM {
        protected $_reload_on_wakeup = FALSE;
	// Relationships
	protected $_has_many = array
	(
		'user_tokens' => array('model' => 'user_token'),
		'roles'       => array('model' => 'role', 'through' => 'roles_users'),
	);
	
	/**
	* Returns array of rules for validation
	* Optionally a specific rule can be returned by passing in the field name
	*
	* @param string Key of rules array to return
	* @return array
	*/
	public function rules($field = NULL) 
	{
		$rules = array
		(
			'username' => array
			(
				'not_empty'  => NULL,
				'min_length' => array(4),
				'max_length' => array(32),
				'regex'      => array('/^[-\pL\pN_.]++$/uD'),
			),
			'password' => array
			(
				'not_empty'  => NULL,
				'min_length' => array(5),
			),
			'email' => array
			(
				'not_empty'  => NULL,
				'min_length' => array(4),
				'max_length' => array(127),
				'email'      => NULL,
			),
		);
		
		if(is_string($field))
		{
			return $rules[$field];
		}
		else
		{
			return $rules;
		}
	}

	/**
	* Returns array of callbacks for validation
	*
	* @return array
	*/
	public function callbacks()
	{
		$callbacks = array
		(
			'username' => array(array($this, 'username_available')),
			'email' => array(array($this, 'email_available')),
		);
	
		return $callbacks;
	}
	
	public function pre_save_filters()
	{
		
		$filters = array
		(
				'password' => array
				(
					'Model_Auth_User::hash_password' => array()
				)
		);
		
		return $filters;
	}
	
	public static function hash_password($password)
	{
		return Auth::instance()->hash_password($password);
	}
	
	/**
	 * Validates login information from an array, and optionally redirects
	 * after a successful login.
	 *
	 * @param   array    values to check
	 * @param   string   URI or URL to redirect to
	 * @return  boolean
	 */
	public function login(array & $array, $redirect = FALSE)
	{
		$array = Validate::factory($array)
			->filter(TRUE, 'trim')
			->rules('username', $this->rules('username'))
			->rules('password', $this->rules('password'));

		// Login starts out invalid
		$status = FALSE;

		if ($array->check())
		{
			// Attempt to load the user
			$this->where('username', '=', $array['username'])->find();

			if ($this->loaded() AND Auth::instance()->login($this, $array['password']))
			{
				if (is_string($redirect))
				{
					// Redirect after a successful login
					Request::instance()->redirect($redirect);
				}

				// Login is successful
				$status = TRUE;
			}
			else
			{
				$array->error('username', 'invalid');
			}
		}

		return $status;
	}


	/**
	 * Does the reverse of unique_key_exists() by triggering error if username exists.
	 * Validation callback.
	 *
	 * @param   Validate  Validate object
	 * @param   string    field name
	 * @return  void
	 */
	public function username_available(Validate $array, $field)
	{
		if ($this->unique_key_exists($array[$field]) AND !$this->loaded())
		{
			$array->error($field, 'username_available', array($array[$field]));
		}
	}

	/**
	 * Does the reverse of unique_key_exists() by triggering error if email exists.
	 * Validation callback.
	 *
	 * @param   Validate  Validate object
	 * @param   string    field name
	 * @return  void
	 */
	public function email_available(Validate $array, $field)
	{
		if ($this->unique_key_exists($array[$field])  AND !$this->loaded())
		{
			$array->error($field, 'email_available', array($array[$field]));
		}
	}

	/**
	 * Tests if a unique key value exists in the database.
	 *
	 * @param   mixed    the value to test
	 * @return  boolean
	 */
	public function unique_key_exists($value)
	{
		return (bool) DB::select(array('COUNT("*")', 'total_count'))
			->from($this->_table_name)
			->where($this->unique_key($value), '=', $value)
			->execute($this->_db)
			->get('total_count');
	}

	/**
	 * Allows a model use both email and username as unique identifiers for login
	 *
	 * @param   string  unique value
	 * @return  string  field name
	 */
	public function unique_key($value)
	{
		return Validate::email($value) ? 'email' : 'username';
	}

	/**
	 * Activates a new user by giving them the "login" role.
	 */
	public function activate()
	{
		$login_role = new Model_Role(array('name' =>'login'));
		$this->add('roles',$login_role);
	}


} // End Auth User Model