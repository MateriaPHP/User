<?php

namespace Materia\User\MVC\Controllers;

/**
 * Login controller class
 *
 * @package Materia.User
 * @author  Filippo Bovo
 * @link    https://lab.alchemica.io/projects/materia/
 **/

use \Materia\Network\Request as Request;
use \Materia\Network\Response as Response;
use \Materia\Development\Patterns\MVC\Model as Model;
use \Materia\Development\Patterns\MVC\View as View;

class Login extends \Materia\Development\Patterns\MVC\Controller {

	protected $_model;
	protected $_view;

	/**
	 * Constructor
	 *
	 * @param	Model	$model
	 * @param	View	$view
	 **/
	public function __construct( Model $model, View $view ) {

		$this->_model = $model;
		$this->_view  = $view;

	}

	/**
	 * @see	\Materia\Development\Patterns\MVC\Controller::get()
	 **/
	public function get( Request $request ) : Response {

		$query = $request->getQuery();

		if ( isset( $query['login'] ) && ( strlen( $query['login'] ) >= 32 ) && $this->_model->authUserFromHash( $query['login'] ) ) {

			// Redirect to password reset
			$redirect = $request->buildURL( 'user/password' );

			return ( new Response() )
				->redirect( $redirect );

		}

		$this->_view->login_form = $this->_model->getForm( TRUE );

		return $this->_view->getResponse();

	}

	/**
	 * @see	\Materia\Development\Patterns\MVC\Controller::post()
	 **/
	public function post( Request $request ) : Response {

		$form = $this->_model->getForm();

		// Try to authenticate
		// if ( $user ) {

		// 	if ( $this->_model->authUser( $user, $data['login_password'] ) ) {

		// 		// Cleaning session
		// 		unset( $_SESSION['form_login_token'] );

		// 		// Redirect to home-page
		// 		$redirect = $request->buildURL();

		// 		return ( new Response() )
		// 			->redirect( $redirect );
		// 	}

		// }
		if ( !$form->getInvalidFields() ) {

			$user = $this->_model->findUser( $_POST['login_user'] );

			if ( $user && $this->_model->authUser( $user, $_POST['login_password'] ) ) {

				if ( isset( $_POST['login_redirect'] ) ) {

					$redirect = $request->buildURL( $_POST['login_redirect'] );

				}
				else {

					$redirect = $request->buildURL( '/' );

				}

				return ( new Response() )->redirect( $redirect );

			}

		}

		return $this->get( $request );

	}

}
