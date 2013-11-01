<?php

namespace kafene;

/*
# kafene\HttpAuthDigest

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

class HttpAuthDigest
{
    # @var String
    protected $ip = '';

    # @var PDO
    protected $db = null;

    # @var Array
    protected $users = [];

    # @var String
    protected $realm = '';

    # @var Integer
    protected $timeout = 0;

    # @var Integer
    protected $maxattempts = 0;

    # @var Boolean
    protected $halt = true;

    # Database Schema
    protected $dbSchema = [
        'ip TEXT NOT NULL UNIQUE',
        'num_attempts INTEGER NOT NULL'
        'first_attempt_time INTEGER NOT NULL',
    ];

    # SQL strings
    protected $sql = [
        'delete' => 'DELETE FROM attempts WHERE first_attempt_time < %d',
        'select' => 'SELECT num_attempts FROM attempts WHERE ip = ?',
        'insert' => 'INSERT INTO attempts (ip, num_attempts, first_attempt_time) VALUES (?, ?, ?)'
        'update' => 'UPDATE attempts SET num_attempts = num_attempts + 1 WHERE ip = ?';
    ];

    /**
     * Initialize the object, set the realm.
     *
     * @param array $options All are optional. Consists of:
     *     - realm: Realm to use
     *     - timeout: Timeout interval before subsequent auth attempts are stopped.
     *     - maxattempts: Max attempts allowed during the timeout interval.
     *     - halt: Stop further auth attempts by exiting the script.
     *     - users: Array of users => passwords or A1 values
     *     - password_a1: If the values in the users array are A1 values.
     * @param PDO $db PDO Connection for database (for logging login attempts).
     * @return kafene\HttpAuth $this or the result of $this->authenticate().
     */
    public function __construct(array $options = array(), \PDO $db)
    {
        $this->realm = empty($options['realm'])
            ? (getenv('SERVER_NAME') ?: 'PROTECTED')
            : (string) $options['realm'];

        $this->timeout = empty($options['timeout'])
            ? 60 # Default 1 minute
            : (int) $options['timeout'];

        $this->maxattempts = empty($options['maxattempts'])
            ? 3 # Default to 3 attempts per $timeout.
            : (int) $options['maxattempts'];

        $this->halt = empty($options['halt'])
            ? true
            : (bool) $options['halt'];

        $this->dbTable = empty($options['db_table'])
            ? 'attempts'
            : (string) $options['db_table'];

        $this->db = $db;
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->db->exec(sprintf(
            "PRAGMA secure_delete=1;".
            "CREATE TABLE IF NOT EXISTS %s (%s)",
            $this->dbTable,
            join(', ', $this->dbSchema));

        # Add any users if specified.
        if (isset($options['users'])) {
            $password_a1 = !empty($options['password_a1']);

            foreach ($options['users'] as $user => $password) {
                $this->addUser($user, $password, $password_a1);
            }

        }

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
     * @param boolean $password_a1 If the password is a pre-calculated A1.
     * @return kafene\HttpAuth $this
     */
    public function addUser($user, $password = null, $password_a1 = false)
    {
        $this->users[$user] = $password_a1
            ? $password
            : md5(sprintf('%s:%s:%s', $user, $this->realm, $password));
        return $this;
    }

    /**
     * Prompt incoming users for credentials and validate them.
     *
     * @return boolean True if the user successfully authenticates.
     */
    public function authenticate()
    {
        if (array_key_exists('PHP_AUTH_DIGEST', $_SERVER)) {
            $digest = $this->parseDigest($_SERVER['PHP_AUTH_DIGEST']);

            if ($digest && (false !== $user = $this->getUser($digest))) {
                $a1 = $this->users[$user];
                $a2 = md5(sprintf(
                    '%s:%s',
                    getenv('REQUEST_METHOD') ?: 'GET',
                    $digest['uri']
                ));
                $valid = md5(sprintf(
                    '%s:%s:%s:%s:%s:%s',
                    $a1,
                    $digest['nonce'],
                    $digest['nc'],
                    $digest['cnonce'],
                    $digest['qop'],
                    $a2
                ));

                if ($digest['response'] === $valid) {
                    return true;
                }
            }
        }

        return $this->prompt();
    }

    /**
     * Check if a user has attempted to validate previously,
     * and increment the number of tries if so, otherwise log
     * this as the first validation attempt.
     */
    protected function checkAttempt()
    {
        if (0 === $attempts = $this->getAttempts()) {
            $this->logAttempt(true);
            return true;
        }
        elseif ((int) $attempts > $this->maxattempts) {

            if ($this->halt) {
                $errstr = 'You may not attempt to log in again ';
                $errstr.= 'for at least another %d seconds.';
                exit(sprintf($errstr, $this->timeout));
            }

            throw new \Exception('Too many validation attempts.', 500);

        }
        else {
            $this->logAttempt();
            return true;
        }
    }

    /**
     * Parse the received digest header and ensure that all
     * required keys are present.
     *
     * @param string $digest PHP Digest header
     * @return array Parsed digest values or false on failure
     */
    function parseDigest($digest)
    {
        $ret = [];
        $keys = 'nonce|nc|cnonce|qop|username|uri|response|opaque|realm|algorithm';
        $need = array_flip(explode('|', $keys));
        $expr = '/(\w+)\s*=\s*(?:([\'"])([^\2]+?)\2|([^\s,&;]+))/x';

        preg_match_all($expr, $digest, $matches, PREG_SET_ORDER);

        foreach ($matches as $m) {
            if (isset($m[1], $m[3])) {
                $ret[$m[1]] = isset($m[4]) ? $m[4] : $m[3];
            }
        }

        $ret = array_intersect_key($ret, $need);
        $valid = 0 === sizeof(array_diff_key($need, $ret));

        if ($valid) {
            $ret['username'] = str_replace(
                ["\\\"", "\\\\"],
                ["\"", "\\"],
                $ret['username']
            );
            return $ret;
        }

        return false;
    }

    /**
     * Ensure that the username that is attmpting to log in
     * is an existing username that can be logged in.
     *
     * @param array $digest parsed HTTP Digest header.
     * @return string The username, if found.
     */
    protected function getUser($digest)
    {
        if (empty($digest['username'])) {
            return $this->prompt();
        }

        $user = $digest['username'];

        if (empty($this->users[$user])) {
            return $this->prompt();
        }

        return $user;
    }

    /**
     * Prompt the client for a username and password, either
     * for initial verification, or after a failed verification.
     *
     * @return boolean False
     */
    protected function prompt()
    {
        $old = time() - (int) $this->timeout);
        $this->db->exec(sprintf($this->sql['delete'], $old));
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
     * Get the number of validation attempts from the current user.
     *
     * @return integer Number of attempts thus far.
     */
    protected function getAttempts()
    {
        $st = $this->db->prepare($this->sql['select']);
        $st->execute([$this->ip]);
        $attemptCount = (int) $st->fetchColumn();
        $st->closeCursor();
        return $attemptCount;
    }

    /**
     * Log a validation attempt into the database.
     *
     * @param boolean $first If it is the first validation attempt from this IP.
     * @return integer Last database insert ID.
     */
    protected function logAttempt($first = false)
    {
        if ($first) {
            $sql = $this->sql['insert'];
            $params = array($this->ip, 1, time());
        } else {
            $sql = $this->sql['update'];
            $params = array($this->ip);
        }

        $st = $this->db->prepare($sql);
        $st->execute($params);

        return $this->db->lastInsertId();
    }
}
