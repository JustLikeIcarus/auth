<?php defined('SYSPATH') or die('No direct access allowed.');

class Model_Auth_User extends ORM {

	// Relationships
	protected $_has_many = array
	(
		'user_tokens' => array('model' => 'user_token'),
		'roles'       => array('model' => 'role', 'through' => 'roles_users'),
	);
	
	/**
	* Returns array of rules for validation
	*
	* @return array
	*/
	public function rules() 
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
				'max_length' => array(42),
			),
			'email' => array
			(
				'not_empty'  => NULL,
				'min_length' => array(4),
				'max_length' => array(127),
				'email'      => NULL,
			),
		);
		
		return $rules;
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
			->rules('username', $this->_rules['username'])
			->rules('password', $this->_rules['password']);

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
		if ($this->unique_key_exists($array[$field]))
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
		if ($this->unique_key_exists($array[$field]))
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
	 * Saves the current object. Will hash password if it was changed.
	 *
	 * @return  ORM
	 */
	public function save()
	{
		if (array_key_exists('password', $this->_changed))
		{
			$this->_object['password'] = Auth::instance()->hash_password($this->_object['password']);
		}
		
		if($this->loaded())
		{
			return parent::update();
		}
		else
		{
			return parent::create();
		}
	}

} // End Auth User Model