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

## Usage

Example (context: in a CI controller):

    public function index()
	{
        $this -> load -> library('digestauth');
        $auth = $this -> digestauth -> authenticate('Realm Name');
        
        if (!empty($auth))
        {
            // Auth successful
            echo '<pre>';
            print_r($auth);
            echo '</pre>';
        }
        else
        {
            // Auth not successful
            echo 'Login details incorrect :(';
        }
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