# ci-digestauth

An(other) authentication library for CodeIgniter. This one uses HTTP Digest authentication, not insecure plaintext form authentication.

**This project is a work in progress -- it works, but is not finished!**

## Installation

### Database
You'll need a DB table called `users`. It needs to be accessible via CI's activerecord implementation. This works:

    CREATE TABLE `users` (
        `username` varchar(50) NOT NULL,
        `realm` varchar(50) NOT NULL,
        `password` varchar(50) NOT NULL,
        `id` int(11) NOT NULL AUTO_INCREMENT,
        PRIMARY KEY (`id`)
    ) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=2 ;

Edit it as required -- there should probably be some more indexes on there.

`password` is a HTTP digest hash:

    md5('username' . ':' . $realm_name . ':' . $password);

For now you'll have to generate your own, but I'm adding basic user management functionality soon.

### Files

Copy `digestauth.php` to `application/libraries`. That's pretty much it.

### PHP: CGI vs Module

If you're running PHP as an apache module, this library should just work right away.

If you're running PHP through CGI, you will need to modify your .htaccess files (specifically the mod_rewrite bit), the reason being that CGI cannot access the PHP_AUTH_DIGEST header. The workaround is to set it as an ENV var and access it through $_ENV['REDIRECT_HTTP_AUTH']

So, if you're using CGI, you'll need to change your rewrites to look like this:

    <IfModule mod_rewrite.c>
        RewriteEngine On
        RewriteBase /
    
        #Removes access to the system folder by users.
        #Additionally this will allow you to create a System.php controller,
        #previously this would not have been possible.
        #'system' can be replaced if you have renamed your system folder.
        RewriteCond %{REQUEST_URI} ^system.*
        RewriteRule ^(.*)$ /index.php?/$1 [env=HTTP_AUTHORIZATION:%{HTTP:Authorization},L]
    
        #Checks to see if the user is attempting to access a valid file,
        #such as an image or css document, if this isn't true it sends the
        #request to index.php
        RewriteCond %{REQUEST_FILENAME} !-f
        RewriteCond %{REQUEST_FILENAME} !-d
        RewriteRule ^(.*)$ index.php?/$1 [env=HTTP_AUTHORIZATION:%{HTTP:Authorization},L]
    </IfModule>

## Usage

Example (context: in a CI controller):

    public function index()
	{
        $this -> load -> library('digestauth');
		$auth = $this -> digestauth -> authenticate('Restricted Area');
		
		// Check auth
		if ($auth -> status === 'initial')
		{
			// Either showing a dialog to the user or user cancelled.
			// Headers already sent, show cancel content
			$this -> output -> append_output('<p>You cancelled login (or something like that). Would you like to <a href="' . current_url() . '">try again</a> or <a href="' . site_url() . '">go to the root page</a>?</p>');
			
			// Prevent more processing
			return;
		}
		else if ($auth -> status === 'invalid')
		{
			// Something bad happened. Look in -> message for exactly what
			$this -> output -> append_output('<p>There was some problem: ' . $auth -> message . '</p>');
			
			// Perform logout to clear browser auth cache, forcing reauth next time
			//$this -> digestauth -> logout(); // does this actually work? More testing required
			return;
		}
		// else: auth is valid!
	}

You can also specify an array of users to accept:

    $auth = $this -> digestauth -> authenticate('Realm Name', 'username'); // For one user, or:
    $auth = $this -> digestauth -> authenticate('Realm Name', array('user1', 'user2', 'user3')); // For multiple users

For more detail, check out the source. It's all fairly heavily commented.

## Current Status

Working methods:
* `set_realm`
* `require_user`
* `authenticate`

Untested Functionality:
* multiple `required_user`s

Unimplemented Functionality:
* User creation/management
* Extendability