<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');

/**

Usage:

// User creation
$this -> digestauth -> create_user('username', 'realm', 'password');
// Call this method for each username/realm combination.

// Auth Process
$this -> digestauth -> set_realm('Restricted Area');
$this -> digestauth -> require_user('username'); // Optional
$auth = $this -> digestauth -> authenticate() // returns an object or BOOL false
if (!empty($auth)) // Must be called before 
{
	// Successful. Print results.
	// Default
	echo $auth -> realm; // 'Restricted Area'
	echo $auth -> username; // 'username'
	
	// Custom (note prefix)
	echo $auth -> x_role; // Custom variable 'role', e.g. 'admin', 'editor', 'guest'
	echo $auth -> x_permissions; // ditto, e.g. 'rw', 'r'
}
else
{
	// Not successful
}

// Alternative to calling set_realm and require_user:
$auth - $this -> digestauth -> authenticate('Restricted Area');
// or
$auth - $this -> digestauth -> authenticate('Restricted Area', 'username');

*/

class digestauth
{
	// !ivars
	var $realm;
	var $required_user; // String or array
	var $user; // Details of the current user (as returned by -> auth()) or false if not logged in
	
	var $tbl_name; // name of the table that user data is stored in. Defaults to 'users'
	protected $ci; // local CI instance
	
	// !constructor
	public function __construct($config=null)
	{
		// Get a copy of CI so we can use the DB classes
		$this -> ci =& get_instance();
		
		// Set tbl_name (defaults to 'users')
		$this -> tbl_name = (empty($config['tbl_name'])) ? 'users' : $config['tbl_name'];
		
		// No-one's logged in already
		$this -> user = false;
	}
	
	// !methods
	// Setters/getters
	public function set_realm($realm)
	{
		// TODO: Any cleaning required?
		$this -> realm = $realm;
	}
	
	public function require_user($user)
	{
		$this -> required_user = $user;
	}
	
	// Utility Methods
	
	/**
	*	Stolen from http://www.php.net/manual/en/features.http-auth.php -- thanks!
	*/
	protected function http_digest_parse($txt)
	{
		// protect against missing data
	    $needed_parts = array('nonce' => 1, 'nc' => 1, 'cnonce' => 1, 'qop' => 1, 'username' => 1, 'uri' => 1, 'response' => 1);
	    $data = array();
	    $keys = implode('|', array_keys($needed_parts));
		
	    preg_match_all('@(' . $keys . ')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', $txt, $matches, PREG_SET_ORDER);
		
	    foreach ($matches as $m) {
	        $data[$m[1]] = $m[3] ? $m[3] : $m[4];
	        unset($needed_parts[$m[1]]);
	    }
		
	    return $needed_parts ? false : $data;
	}
	
	// User management
	
	/**
	*	TODO
	*	Multipurpose function. Either creates or alters a user/realm combination.
	*	E.G. user 'barnabywalters' in two realms 'realm1' and 'realm2' requires a DB record for each -- identical usernames, but different realm and hash values.
	*	@return bool success
	*/
	public function create_user($username, $realm, $password, $extra=null)
	{
		// Validate data
		$username = trim($username);
		
		// Compute Hash
		$hash = md5($username . ':' . $realm . ':' . $password);
		
		// Check current state of db
		
		// Add to DB
		
		// Return
	}
	
	// Auth methods
	public function authenticate($realm = null, $username = null)
	{
		// If args are valid, overwrite current required user and realm.
		if (isset($realm)) $this -> realm = $realm;
		if (isset($username)) $this -> required_user = $username;
		
		// Check for valid ivars
		if (empty($this -> realm))
		{
			// No valid realm, cannot perform auth
			show_error('No realm provided for auth!');
			return (object) array('status' => 'invalid');
		}
		
		// Check for auth headers, send if they're not there
		// Get auth headers
		$auth_headers = ''; // Default to empty string
		if (!empty($_SERVER['PHP_AUTH_DIGEST']))
		{
			// headers sent AND running as an apache module
			$auth_headers = $_SERVER['PHP_AUTH_DIGEST'];
		}
		else if (!empty($_ENV['REDIRECT_HTTP_AUTHORIZATION']))
		{
			// headers sent AND running under CGI
			
			// Should probably check for digest vs basic here
			
			$auth_headers = $_ENV['REDIRECT_HTTP_AUTHORIZATION'];
		}
		
		if (empty($auth_headers) OR $this -> ci -> session -> flashdata('auth_status') == 'invalid')
		{
		    $this -> ci -> output -> set_header('HTTP/1.1 401 Unauthorized');
		    $this -> ci -> output -> set_header('WWW-Authenticate: Digest realm="' . $this -> realm.
				'",qop="auth",nonce="' . uniqid() . '",opaque="' . md5($this -> realm) . '"');
		    
		    return (object) array('status' => 'initial');
		}
		
		// Parse auth headers
		if (!($data = $this -> http_digest_parse($auth_headers))) return (object) array('status' => 'invalid', 'message' => 'invalid_http_data'); // Bad credentials. TODO: What sort of meaningful error can we give here?
		
		// Check to see if the client user matches any required_user given
		if (!empty($this -> required_user))
		{
			// We're looking to authenticate a particular user or set of users.
			
			// Is required_user a string or array? Make array regardless
			if (is_string($this -> required_user))
			{
				$this -> required_user = array($this -> required_user); // weird line of code...
			}
			
			// Check $data['username'] against $this -> required_user
			if (!in_array($data['username'], $this -> required_user))
			{
				$this -> ci -> session -> set_flashdata('auth_status', 'invalid');
				return (object) array('status' => 'invalid', 'message' => 'user_not_permitted');
			}
		}
		
		// Check user data against db
		$query = $this -> ci -> db -> from($this -> tbl_name)
			-> where('username', $data['username'])
			-> where('realm', $this -> realm) -> get();
		
		if ($query -> num_rows() !== 1)
		{
			$this -> ci -> session -> set_flashdata('auth_status', 'invalid');
			return (object) array('status' => 'invalid', 'message' => 'invalid_user');
		}
		
		// Get hash
		$user_hash = $query -> row() -> password;
		
		// Compute valid response (code stolen from http://www.php.net/manual/en/features.http-auth.php -- thanks!
		$A2 = md5($_SERVER['REQUEST_METHOD'] . ':' .$data['uri']);
		$valid_response = md5($user_hash . ':' . $data['nonce'] . ':' . $data['nc'] . ':' . $data['cnonce'] . ':' . $data['qop'] . ':' . $A2);
		
		// Correct?
		if ($data['response'] !== $valid_response)
		{
			$this -> ci -> session -> set_flashdata('auth_status', 'invalid');
			return (object) array('status' => 'invalid', 'message' => 'invalid_password');
		}
		
		// Store current user details
		$this -> user = $query -> row();
		
		// Result
		return (object) array('status' => 'logged_in');
	}
	
	/**
	*	(In theory) logs out the current user.
	*	Sends HTTP headers so must be called before any are sent by the rest of the script
	*/
	public function logout()
	{
		// Remove current user details
		$this -> user = false;
		
		// Send 401 header to clear auth chache (in most cases)
		$this -> ci -> session -> set_flashdata('auth_status', 'invalid');
		$this -> ci -> output -> set_header('HTTP/1.1 401 Unauthorized');
		$this -> ci -> output -> set_header('WWW-Authenticate: Digest realm="' . $this -> realm.
				'",qop="auth",nonce="' . uniqid() . '",opaque="' . md5($this -> realm) . '"');
	}
	
}

/* EOF digestauth.php */