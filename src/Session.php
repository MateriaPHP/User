<?php

namespace Materia\User;

/**
 * Session handler class
 *
 * @package	Materia.Session
 * @author	Filippo "Pirosauro" Bovo
 * @link	http://lab.alchemica.org/projects/materia/
 **/

use \Materia\Security\Input as Input;

class Session extends \SessionHandler {

	protected $_key;
	protected $_name;
	protected $_user;
	protected $_cookie;
	protected $_fingerprint;

	/**
	 * Constructor
	 *
	 * @param   string  $key        encryption key (24 chars long)
	 * @param   string  $name       session name
	 * @param   array   $cookie     session cookie params
	 **/
	public function __construct( string $key, string $name = NULL, array $cookie = [] ) {

		$this->_key         = $key;
		$this->_name        = $name;
		$this->_cookie      = $cookie;
		$this->_fingerprint = $this->getFingerprint();

		$this->_cookie += [
			'lifetime' => 0,
			'path'     => @ini_get( 'session.cookie_path' ),
			'domain'   => @ini_get( 'session.cookie_domain' ),
			'secure'   => isset( $_SERVER['HTTPS'] ),
			'httponly' => TRUE,
		];

		// Initialize
		@ini_set( 'session.use_cookies', 1 );
		@ini_set( 'session.use_only_cookies', 1 );

		if ( $this->_name ) {

			session_name( $this->_name );

		}
		else {

			$this->_name = session_name();

		}

		session_set_cookie_params(
			$this->_cookie['lifetime'],
			$this->_cookie['path'],
			$this->_cookie['domain'],
			$this->_cookie['secure'],
			$this->_cookie['httponly']
		);

	}

	/**
	 * Returns session ID
	 *
	 * @return  string
	 **/
	public function getID() {

		if ( session_status() === PHP_SESSION_ACTIVE ) {

			return session_id();

		}

	}

	/**
	 * Returns session name
	 *
	 * @return  string
	 **/
	public function getName() {

		return $this->_name;

	}

	/**
	 * Session start
	 *
	 * @return  bool
	 **/
	public function start() {

		if ( session_status() === PHP_SESSION_NONE ) {

			if ( $_COOKIE instanceof Input ) {

				$_COOKIE->setFilter( $this->_name, function( $input ) {

					return preg_replace( '#[\W]+#', '', $input );

				} );

				if ( isset( $_COOKIE[$this->_name] ) ) {

					session_id( $_COOKIE[$this->_name] );

				}

			}

			if ( session_start() ) {

				$_SESSION['_last_activity']  =  time();

				if ( $this->_fingerprint && !isset( $_SESSION['_fingerprint'] ) ) {

					$_SESSION['_fingerprint'] = $this->_fingerprint;

				}

				return TRUE;
				return ( mt_rand( 0, 4 ) === 0 ) ? $this->regenerate() : TRUE;

			}

		}

		return FALSE;

	}

	/**
	 * Remove the session
	 *
	 * @return  bool
	 **/
	public function forget() {

		if ( session_status() !== PHP_SESSION_ACTIVE ) {

			return FALSE;

		}

		$_SESSION = [];

		setcookie(
			$this->_name,
			'',
			time() - ( 24 * 60 * 60 ),
			$this->_cookie['path'],
			$this->_cookie['domain'],
			$this->_cookie['secure'],
			$this->_cookie['httponly']
		);

		return session_destroy();

	}

	/**
	 * Regenerate the session
	 *
	 * @return  string
	 **/
	public function regenerate() {

		return session_regenerate_id( TRUE );

	}

	/**
	 * @see \SessionHandler::read()
	 **/
	public function read( $id ) {

		if ( $data = parent::read( $id ) ) {

			return ( string ) mcrypt_decrypt( MCRYPT_3DES, $this->_key, $data, MCRYPT_MODE_ECB );

		}
		else {

			return '';

		}

	}

	/**
	 * @see \SessionHandler::write()
	 **/
	public function write( $id, $data ) {

		return parent::write( $id, mcrypt_encrypt( MCRYPT_3DES, $this->_key, $data, MCRYPT_MODE_ECB ) );

	}

	/**
	 * Checks whatever the session is expired or not
	 *
	 * @param   integer $ttl
	 * @return  bool
	 **/
	public function isExpired( $ttl = 30 ) {

		$last = isset( $_SESSION['_last_activity'] ) ? $_SESSION['_last_activity'] : 0;

		if ( $last && ( ( time() - $last ) > ( $ttl * 60 ) ) ) {

			return TRUE;

		}

		return FALSE;

	}

	/**
	 * Checks whatever the session has a valid fingerprint or not
	 *
	 * @return  bool
	 **/
	public function isFingerprinted() {

		if ( isset( $_SESSION['_fingerprint'] ) ) {

			return $_SESSION['_fingerprint'] === $this->_fingerprint;

		}

		return TRUE;

	}

	/**
	 * Calculate fingerprint
	 *
	 * @return  string|null
	 **/
	protected function getFingerprint() {

		$hex = '';
		$ip  = $_SERVER['REMOTE_ADDR'];

		if( strpos( $ip, ',' ) !== FALSE ) {

			$split = explode( ',', $ip );
			$ip    = trim( $split[0] );

		}

		$is_ipv6 = FALSE;
		$is_ipv4 = FALSE;

		if( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) !== FALSE ) {

			$is_ipv6 = TRUE;

		}
		else if( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) !== FALSE ) {

			$is_ipv4 = TRUE;

		}
		else {

			return;

		}

		// IPv4 format
		if( $is_ipv4 ) {

			$parts = explode( '.', $ip );

			for( $i = 0; $i < 4; $i++ ) {

				$parts[$i] = str_pad( dechex( $parts[$i] ), 2, '0', STR_PAD_LEFT );

			}

			$ip  = '::' . $parts[0] . $parts[1] . ':' . $parts[2] . $parts[3];
			$hex = join( '', $parts );

		}
		// IPv6 format
		else {

			$parts = explode( ':', $ip );
			// If this is mixed IPv6/IPv4, convert end to IPv6 value
			$count = count( $parts ) - 1;

			if( filter_var( $parts[$count], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) !== FALSE ) {

				$parts_v4 = explode( '.', $parts[$count] );

				for( $i = 0; $i < 4; $i++ ) {

					$parts_v4[$i] = str_pad( dechex( $parts_v4[$i] ), 2, '0', STR_PAD_LEFT );

				}

				$parts[$count] = $parts_v4[0] . $parts_v4[1];
				$parts[]       = $parts_v4[2] . $parts_v4[3];

			}

			$missing  = 8 - count( $parts );
			$expanded = [];
			$done     = FALSE;

			foreach( $parts as $part ) {

				if( !$done && ( $part == '' ) ) {

					for( $i = 0; $i <= $missing; $i++ ) {

						$expanded[] = '0000';

					}

					$done = TRUE;

				}
				else {

					$expanded[] = $part;

				}

			}

			foreach( $expanded as &$part ) {

				$part = str_pad( $part, 4, '0', STR_PAD_LEFT );

			}

			$ip  = join( ':', $expanded );
			$hex = join( '', $expanded );

		}

		// Validate the final IP
		if( !filter_var( $ip, FILTER_VALIDATE_IP ) ) {

			return;

		}

		return ( md5( $_SERVER['HTTP_USER_AGENT'] . strtolower( str_pad( $hex, 32, '0', STR_PAD_LEFT ) ) ) );

	}

	/**
	 * Checks whatever the session is valid
	 *
	 * @return  bool
	 **/
	public function isValid() {

		return !$this->isExpired() && $this->isFingerprinted();

	}

}
