<?php

namespace Materia\User\Data\Records;

/**
 * User Entity class
 *
 * @package Materia.User
 * @author  Filippo "Pirosauro" Bovo
 * @link    http://lab.alchemica.org/projects/materia/
 **/

class User extends \Materia\EAV\Record implements \Serializable {

	const NAME        = 'user';
	const TABLE       = 'users';
	const PREFIX      = 'user_';
	const PRIMARY_KEY = 'id';

	protected static $_properties = [
		'password' => 'Password',
	];

	/**
	 * @see \Searializable::serialize()
	 **/
	public function serialize() {

		return serialize( [ $this->_data, $this->_values, static::$_attributes ] );

	}

	/**
	 * @see \Searializable::unserialize()
	 **/
	public function unserialize( $data ) {

		list( $this->_data, $this->_values, static::$_attributes ) = unserialize( $data );

	}

	public function setPassword( string $password ) {

		// Warning: password's policy should be defined on model (before calling this method)
		static $options = [
			'cost'	 =>	12,
		];

		$this->_data['password'] = password_hash( $password, PASSWORD_BCRYPT, $options );

	}

	public function getPassword() {

		// Always return empty password (avoid password hash reveal)
		return NULL;

	}

	public function validatePassword( string $password ) : bool {

		// Avoid empty passwords
		if ( !isset( $this->_data['password'] ) || !$this->_data['password'] || !$password ) {

			return FALSE;

		}

		return password_verify( $password, $this->_data['password'] );

	}

}
