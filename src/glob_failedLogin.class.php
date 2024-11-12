<?php




/**
 * @global int BLOCKED_IP_HOURS_INTERVAL
 * @global int MAX_ALLOWED_LOGIN_ATTEMPTS
 */
class glob_failedLogin extends glob_dbaseTablePrimary {

    /**
     * @var int
     */
    public $id;

    /**
     * @var string
     */
	public $ip;

    /**
     * @var int
     */
    public $type;

    /**
     * @var string
     */
    public $payload;

    /**
     * @var string
     */
    public $timeCreated;




    /**
     * @global PDO $pdo
     * @global int BLOCKED_IP_HOURS_INTERVAL
     * @static
     * @return void
     */
    public static function db_deleteOld() {

        global $pdo;

        $query = 'DELETE FROM `' . __CLASS__ . '` WHERE timeCreated < DATE_SUB( NOW(), INTERVAL ' . BLOCKED_IP_HOURS_INTERVAL . ' HOUR);';

        $stmt = $pdo->prepare( $query );

        $stmt->execute();

    }

    /**
     * @param int $type
     * @return void
     */
    public static function new( $type ) {

        if ( empty( $_SERVER[ 'HTTP_CLIENT_IP' ] ) === false ) {

            $ip = new self();
            $ip->ip = $_SERVER[ 'HTTP_CLIENT_IP' ];
            $ip->type = $type;
            $ip->set_payload();
            $ip->db_insert();

        }

        if ( empty( $_SERVER[ 'HTTP_X_FORWARDED_FOR' ] ) === false ) {

            $ip = new self();
            $ip->ip = $_SERVER[ 'HTTP_X_FORWARDED_FOR' ];
            $ip->type = $type;
            $ip->set_payload();
            $ip->db_insert();

        }

        if ( empty( $_SERVER[ 'REMOTE_ADDR' ] ) === false ) {

            $ip = new self();
            $ip->ip = $_SERVER[ 'REMOTE_ADDR' ];
            $ip->type = $type;
            $ip->set_payload();
            $ip->db_insert();

        }

    }

    /**
     * @global int MAX_ALLOWED_LOGIN_ATTEMPTS
     * @return boolean
     */
    public static function isAllowedToLogin() {

        if ( empty( $_SERVER[ 'HTTP_CLIENT_IP' ] ) === false ) {

            $logins = glob_failedLogin::db_getAllWhere( 'ip', $_SERVER[ 'HTTP_CLIENT_IP' ] );

            if ( count( $logins ) > MAX_ALLOWED_LOGIN_ATTEMPTS ) {

                return false;

            }

        }

        if ( empty( $_SERVER[ 'HTTP_X_FORWARDED_FOR' ] ) === false ) {

            $logins = glob_failedLogin::db_getAllWhere( 'ip', $_SERVER[ 'HTTP_X_FORWARDED_FOR' ] );

            if ( count( $logins ) > MAX_ALLOWED_LOGIN_ATTEMPTS ) {

                return false;

            }

        }

        if ( empty( $_SERVER[ 'REMOTE_ADDR' ] ) === false ) {

            $logins = glob_failedLogin::db_getAllWhere( 'ip', $_SERVER[ 'REMOTE_ADDR' ] );

            if ( count( $logins ) > MAX_ALLOWED_LOGIN_ATTEMPTS ) {

                return false;

            }

        }

        return true;

    }




    /**
     * @return glob_failedLogin
     */
    public function __construct() {}

    /**
     * @return void
     */
    public function set_payload() {

        $payload = [
            'SERVER' => $_SERVER,
            'POST' => $_POST,
            'GET' => $_GET
        ];

        $this->payload = json_encode( $payload );

    }

}