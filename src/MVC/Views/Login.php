<?php

namespace Materia\User\MVC\Views;

/**
 * Login view class
 *
 * @package Materia.User
 * @author  Filippo Bovo
 * @link    https://lab.alchemica.io/projects/materia/
 **/

use \Materia\Development\Patterns\MVC\Views\HTML\Template as Template;
use \Materia\I18n\Translator as Translator;
use \Materia\Network\Request as Request;
use \Materia\Network\Response as Response;
use \Materia\Content\MVC\Views\HTML\Tags\Form as Form;
use \Materia\Content\MVC\Views\HTML\Tags\Text as Text;
use \Materia\Content\MVC\Views\HTML\Tags\Password as Password;
use \Materia\Content\MVC\Views\HTML\Tags\Hidden as Hidden;

class Login extends \Materia\Development\Patterns\MVC\Views\HTML {

	protected $_translator;

	/**
	 * Constructor
	 *
	 * @param	Translator	$translator
	 **/
	public function __construct( Template $template, Translator $translator ) {

		parent::__construct( $template );

		$this->_translator = $translator;

	}

	/**
	 * @see	\Materia\Development\MVC\View::getResponse()
	 **/
	public function getResponse( Response $response = NULL ) : Response {

		if ( !$response ) {

			$response = new	Response();

		}

		$response->setBody( $this->_template->render( [ 'User/Login' ], $this ) );

		return $response;

	}

}
