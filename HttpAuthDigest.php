<?php

namespace kafene;

/**
# kafene\HttpAuth

A PHP class for user logins via HTTP Digest Authentication.

It includes a simple brute force protection by not allowing
the same IP address to attempt to log in more than X number
of times in the same interval. Both the interval and number
of allowed attempts are user specified.

Even though digest auth has the `nc` value that tracks the
number of login attempts, this could be spoofed by a malicious
user and so instead this tracks attempts independently.

Example usage:

```php
$auth = new kafene\HttpAuthDigest;
$auth->addUser('user', 'pass');
if($auth->authenticate()) {
    print 'Welcome!';
}
```

This is free and unencumbered software released into the public domain.
For more information, please refer to <http://unlicense.org/>
*/

class HttpAuthDigest {
    protected $ip = ''; # @var String
    protected $db = null; # @var PDO
    protected $required = []; # @var array
    protected $users = []; # @var Array
    protected $realm = ''; # @var String
    protected $timeout = 0; # @var Integer
    protected $maxattempts = 0; # @var Integer
    protected $lockfile = ''; # @var String
    protected $halt = true; # @var Boolean

    /**
     * Initialize the object, set the realm.
     *
     * @param array $options All are optional. Consists of:
     *     - realm: Realm to use
     *     - lockfile: filename of sqlite db file.
     *     - timeout: Timeout interval before subsequent auth attempts are stopped.
     *     - maxattempts: Max attempts allowed during the timeout interval.
     *     - halt: Stop further auth attempts by exiting the script.
     *     - users: Array of users => passwords or A1 values
     *     - password_a1: If the values in the users array are A1 values.
     * @return kafene\HttpAuth $this or the result of $this->authenticate().
     */
    public function __construct(array $options = []) {
        $this->realm = isset($options['realm'])
            ? $options['realm']
            : (getenv('SERVER_NAME') ?: 'PROTECTED');
  
        $this->lockfile = isset($options['lockfile'])
            ? $options['lockfile']
            : 'http_auth_lock.db';

        $this->timeout = isset($options['timeout'])
            ? (int) $options['timeout']
            : 60; # Default 1 minute
        
        $this->maxattempts = isset($options['maxattempts'])
            ? (int) $options['maxattempts']
            : 3; # Default to 3 attempts per $timeout.
        
        $this->halt = isset($options['halt'])
            ? (bool) $options['halt']
            : true;

        # Add any users if specified.
        $this->users = [];
        if(isset($options['users'])) {
            $a1 = isset($options['password_a1'])
                ? (bool) $options['password_a1']
                : false;
            foreach($options['users'] as $user => $password) {
                $this->addUser($user, $password, $a1);
            }
        }

        # Set up required keys from the parsed digest.
        $this->required = $required = [
            'algorithm', 'realm', 'uri', 'username', 'nonce',
            'cnonce', 'opaque', 'qop', 'nc', 'response'
        ];
        
        # Set up remote user IP.
        $this->ip = sprintf('%u', ip2long(getenv('REMOTE_ADDR')));

        return $this;
    }

    /**
     * Add a user and password combo, or a combination of
     * username and pre-calculated A1 value (e.g. from a database
     * where you don't wish to store the raw password).
     *
     * @param string $user Username
     * @param string $password Password or A1 value
     * @param boolean $password_as_a1 If the password is a pre-calculated A1.
     * @return kafene\HttpAuth $this
     */
    public function addUser($user, $password = null, $password_as_a1 = false) {
        $this->users[$user] = $password_as_a1
            ? $password
            : md5(sprintf('%s:%s:%s', $user, $this->realm, $password));
        return $this;
    }

    /**
     * Prompt incoming users for credentials and validate them.
     *
     * @return boolean True if the user successfully authenticates.
     */
    public function authenticate() {
        $digest = $this->getDigest();
        if(false !== $user = $this->getUser($digest)) {
            $a1 = $this->users[$user];
            $a2 = md5(sprintf(
                '%s:%s',
                getenv('REQUEST_METHOD') ?: 'GET',
                $digest['uri']
            ));
            $valid = $digest['response'] === md5(sprintf(
                '%s:%s:%s:%s:%s:%s',
                $a1,
                $digest['nonce'],
                $digest['nc'],
                $digest['cnonce'],
                $digest['qop'],
                $a2
            ));
            if($valid) {
                return true;
            }
        }
        return $this->prompt();
    }

    /**
     * Check if a user has attempted to validate previously,
     * and increment the number of tries if so, otherwise log
     * this as the first validation attempt.
     */
    protected function checkAttempt() {
        if(0 === $attempts = $this->getAttempts()) {
            $this->logAttempt(true);
            return true;
        } elseif((int) $attempts > $this->maxattempts) {
            if($this->halt) {
                $errstr = 'You may not attempt to log in again for at least another %d seconds.';
                exit(sprintf($errstr, $this->timeout));
            }
            throw new \Exception('Too many validation attempts, operation halted.', 500);
        } else {
            $this->logAttempt();
            return true;
        }
    }

    /**
     * Parse the received digest header and ensure that all
     * required keys are present.
     *
     * @param string $digest PHP Digest header
     * @return array Parsed digest values
     */
    protected function getDigest() {
        if(!empty($_SERVER['PHP_AUTH_DIGEST'])) {
            $digest = $_SERVER['PHP_AUTH_DIGEST'];
            if(preg_match_all('/(\w+)="?([^",]+)"?/', $digest, $m)) {
                $recd = array_intersect_key($this->required, $m[1]);
                $recd = array_filter(array_map('trim', $recd));
                if($recd == $this->required && count($m[2]) === count($recd)) {
                    return array_combine($m[1], $m[2]);
                }
            }
        }
        return $this->prompt();
    }

    /**
     * Ensure that the username that is attmpting to log in
     * is an existing username that can be logged in.
     *
     * @param array $digest parsed HTTP Digest header.
     * @return string The username, if found.
     */
    protected function getUser($digest) {
        if(empty($digest['username'])) { return $this->prompt(); }
        $user = $digest['username'];
        if(empty($this->users[$user])) { return $this->prompt(); }
        # var_dump($user, $digest, $this->users, $_SERVER['PHP_AUTH_DIGEST']);die;
        return $user;
    }

    /**
     * Prompt the client for a username and password, either
     * for initial verification, or after a failed verification.
     *
     * @return boolean False
     */
    protected function prompt() {
        $this->openDatabase();
        $this->checkAttempt();
        $message = 'HTTP/1.1 401 Unauthorized';
        header($message, true, 401);
        header(sprintf(
            'WWW-Authenticate: Digest realm="%s", qop="auth", nonce="%s", opaque="%s"',
            $this->realm,
            trim(base64_encode(uniqid('', true)), '='),
            md5($this->realm)
        ));
        if(false !== $this->halt) {
            exit($message);
        }
        return false;
    }
    
    /**
     * Open the database connection used for logging attempts.
     *
     * @return null
     */
    protected function openDatabase() {
        $create = !file_exists($this->lockfile);
        $this->db = new \PDO('sqlite:'.$this->lockfile);
        $this->db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        if($create) {
            $this->db->query('CREATE TABLE IF NOT EXISTS attempts (
                ip TEXT NOT NULL UNIQUE,
                num_attempts INTEGER NOT NULL,
                first_attempt_time INTEGER NOT NULL
            )');
        }
        $this->db->exec('PRAGMA secure_delete=1');
        # Clear validation attempts that are older than the validation interval.
        $sql = 'DELETE FROM attempts WHERE first_attempt_time < %d';
        $old = time() - (int) $this->timeout;
        $this->db->exec(sprintf($sql, $old));
    }

    /**
     * Get the number of validation attempts from the current user.
     *
     * @return integer Number of attempts thus far.
     */
    protected function getAttempts() {
        $stmt = $this->db->prepare('SELECT num_attempts FROM attempts WHERE ip = ?');
        $stmt->execute([$this->ip]);
        $num_attempts = (int) $stmt->fetchColumn();
        $stmt->closeCursor();
        return $num_attempts;
    }

    /**
     * Log a validation attempt into the database.
     *
     * @param boolean $first If it is the first validation attempt from this IP.
     * @return integer Last database insert ID.
     */
    protected function logAttempt($first = false) {
        $sql = $first
            ? 'INSERT INTO attempts (ip, num_attempts, first_attempt_time) VALUES (?, ?, ?)'
            : 'UPDATE attempts SET num_attempts = num_attempts + 1 WHERE ip = ?';
        $params = $first
            ? [$this->ip, 1, time()]
            : [$this->ip];
        #var_dump($sql, $params, $this->db->query('SELECT * FROM attempts')->fetchAll());die;
        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return $this->db->lastInsertId();
    }
}
