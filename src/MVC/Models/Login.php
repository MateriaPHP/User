<?php

namespace Materia\User\MVC\Models;

/**
 * Login model, handles auth logic
 *
 * @package	Materia.User
 * @author	Filippo Bovo
 * @link	https://lab.alchemica.io/projects/Materia/
 **/

use \Materia\Data\SQL\Connection as Connection;
use \Materia\I18n\Translator as Translator;
use \Materia\User\Data\EAV\User as User;
use \Materia\Development\Patterns\MVC\Views\HTML\Tags as Tags;
use \Materia\Security\Filters as Filters;

class Login implements \Materia\Development\Patterns\MVC\Model {

	protected $_connection;
	protected $_translator;
	protected $_form;

	/**
	 * Constructor
	 *
	 * @param	Connection	$connection
	 * @param	Translator	$translator
	 **/
	public function __construct( Connection $connection, Translator $translator ) {

		$this->_connection = $connection;
		$this->_translator = $translator;

	}

	/**
	 * Find user by email address or mobile number
	 *
	 * @param	string	$input
	 * @return	mixed
	 **/
	public function findUser( string $input ) {

		if ( strpos( $input, '@' ) ) {

			return $this->_connection->select()
			                         ->from( User::TABLE )
			                         ->where( 'user_email', '=', $input )
			                         ->first( User::class );

		}
		else {

			return $this->_connection
			            ->select()
			            ->from( User::TABLE )
			            ->where( 'user_mobile', '=', $input )
			            ->first( User::class );

		}
	}

	/**
	 * User logon
	 *
	 * @param	User	$user
	 * @return	bool
	 **/
	public function authUser( User $user, string $password ) : bool {

		if ( $user->validatePassword( $password ) ) {

			$_SESSION['current_user'] = $user;

			return TRUE;

		}

		return FALSE;

	}

	/**
	 * User logon from hash
	 *
	 * @param	User	$user
	 * @return	bool
	 **/
	public function authUserFromHash( string $hash ) : bool {

		if ( strlen( $hash ) >= 32 ) {

			$user = $this->_connection
			             ->select()
			             ->from( User::TABLE )
			             ->where( 'user_hash', '=', $hash )
			             ->first( User::class );

			if ( $user && !$user->password ) {

				$_SESSION['current_user'] = $user;

				return TRUE;

			}

		}

		return FALSE;

	}

	/**
	 * Returns login form
	 *
	 * @param	bool	$regenerate_token
	 * @return	Form
	 **/
	public function getForm( bool $regenerate_token = FALSE ) {

		if ( !isset( $this->_form ) ) {

			$this->_form = new Tags\Form( [
				'method' => 'POST',
				'id'     => 'user-login',
			] );

			// User
			$user = new Tags\Text( [
				'name'        => 'login_user',
				'placeholder' => $this->_translator->translate( 'User', 'Email or Mobile number' ),
				'required'    => TRUE,
			] );

			$_POST->setFilter( 'login_user', function( $input ) {

				return ( new Filters\XSS() )->sanitize( $input );

			} );

			$user->setValidator( function( $input ) {

				return ( filter_var( $input, FILTER_VALIDATE_EMAIL ) || preg_match( '#[0-9]{6,16}#', $input ) );

			} );

			$this->_form->addChildBefore( $user );

			// Password
			$pass = new Tags\Password( [
				'name'        => 'login_password',
				'placeholder' => $this->_translator->translate( 'User', 'Password' ),
				'required'    => TRUE,
			] );

			$_POST->setFilter( 'login_password', function( $input ) {

				return $input;

			} );

			$pass->setValidator( function( $input ) {

				return ( strlen( $input ) >= 6 );

			} );

			$this->_form->addChildBefore( $pass );

			// Token
			if ( !isset( $_SESSION['form_login_token'] ) || $regenerate_token ) {

				$_SESSION['form_login_token'] = $this->_form->generateToken();

			}

			$token = new Tags\Hidden( [
				'name'  => 'login_token',
				'value' => $_SESSION['form_login_token'],
			] );

			$_POST->setFilter( 'login_token', function( $input ) {

				return ( new Filters\XSS() )->sanitize( $input );

			} );

			$token->setValidator( function( $input ) {

				return ( isset( $_SESSION['form_login_token'] ) && ( $_SESSION['form_login_token'] == $input ) );

			} );

			$this->_form->addChildAfter( $token );

		}

		return $this->_form;

	}

}
