<?php defined('SYSPATH') or die('No direct access allowed.');

abstract class Auth extends Kohana_Auth {

private static $instances;

	/**
	 * Singleton pattern
	 *
	 * @return Auth
	 */
	public static function instance()
	{
		if ( ! isset(self::$instances))
		{
echo "instances not set";
			// Load the configuration for this type
			$config = Kohana::config('auth');

			if ( ! $type = $config->get('driver'))
			{
				$type = 'ORM';
			}

			// Set the session class name
			$class = 'Auth_'.ucfirst($type);

			// Create a new session instance
			self::$instances = new $class($config);
		}
 echo Kohana::debug(self::$instances);
		return self::$instances;
	}


 }