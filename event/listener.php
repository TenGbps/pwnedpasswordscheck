<?php
/**
*
* @package phpBB Extension - Pwned Passwords Check
* @copyright (c) 2024 @TenGbps
* @license http://opensource.org/licenses/gpl-2.0.php GNU General Public License v2
*
*/

namespace tengbps\pwnedpasswordscheck\event;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Class listener
 *
 * This class handles events related to user password checks against a known breached password database.
 */
class listener implements EventSubscriberInterface
{
    // Properties to hold instances of necessary classes
    protected $user;         // User object for managing user data
    protected $request;      // Request object for handling HTTP requests
    protected $db;           // Database driver interface for executing SQL queries

    /**
     * Constructor method for the listener class.
     *
     * @param \phpbb\user $user User object
     * @param \phpbb\request\request $request Request object
     * @param \phpbb\config\db_text $config_text Config object
     * @param \phpbb\db\driver\driver_interface $db Database driver object
     */
    public function __construct(\phpbb\user $user, \phpbb\request\request $request, \phpbb\config\db_text $config_text, \phpbb\db\driver\driver_interface $db)
    {
        $this->user = $user;             // Initialize user
        $this->request = $request;       // Initialize request
        $this->config_text = $config_text; // Initialize config text
        $this->db = $db;                 // Initialize database

        // Load the language files for the current user's language
        $this->user->add_lang_ext('tengbps/pwnedpasswordscheck', 'common');
    }

    /**
     * Specifies the events that this listener will subscribe to.
     *
     * @return array The events and their corresponding methods
     */
    public static function getSubscribedEvents()
    {
        return [
            'core.ucp_profile_reg_details_sql_ary' => 'check_password_on_change', // Event for checking password on change
            'core.auth_login_session_create_before' => 'check_password_on_login', // Event for checking password on login
        ];
    }

    /**
     * Checks if the new password is in the breached database during password change.
     *
     * @param \phpbb\event\data $event The event data containing the new password
     */
    public function check_password_on_change($event)
    {
        $data = $event['data']; // Extract event data
        // Check if the new password is set and if it's breached
        if (isset($data["new_password"]) && $this->is_password_pwned($data["new_password"])) {
            // Trigger a warning if the password is compromised
            trigger_error($this->user->lang['PASSWORD_BREACHED'], E_USER_WARNING);
        }
    }

    /**
     * Checks if the password is in the breached database during login
     * and forces password change if found.
     *
     * @param \phpbb\event\data $event The event data for login
     */
    public function check_password_on_login($event)
    {
        // Retrieve username and password from the request
        $username = $this->request->variable('username', '', true); // Clean input for security
        $password = $this->request->variable('password', '', true); // Clean input for security

        // Get user ID based on username
        $user_id = $this->get_user_id_by_username($username);

        // Retrieve the user's current password hash from the database
        $sql = 'SELECT user_password FROM ' . USERS_TABLE . ' WHERE user_id = ' . (int)$user_id;
        $result = $this->db->sql_query($sql);
        $row = $this->db->sql_fetchrow($result);
        $this->db->sql_freeresult($result);


        // If user ID or stored password is not found, exit the function
        if (!$user_id || !$row) {
            return;
        }

        $stored_password_hash = $row['user_password'];

        // Verify if the entered password matches the stored password
        if (!phpbb_check_hash($password, $stored_password_hash)) {
            // Password does not match, no need to proceed further
            return;
        }

        // Check if the password is breached
        if ($this->is_password_pwned($password))
        {
            // Force password change if the password is compromised
            $this->force_password_change($user_id);
        }
    }

    /**
     * Checks if the password has been breached using the Pwned Passwords API.
     *
     * @param string $password The password to check
     * @return bool True if the password is breached, False otherwise.
     */
    private function is_password_pwned($password)
    {
        // Hash the password using SHA-1 and convert it to uppercase
        $hash = strtoupper(sha1($password));
        // Extract the first 5 characters as prefix
        $prefix = substr($hash, 0, 5);
        // Get the remaining characters as suffix
        $suffix = substr($hash, 5);

        // Construct the API URL for checking the password
        $url = 'https://api.pwnedpasswords.com/range/' . $prefix;
        // Fetch the response from the API
        $response = file_get_contents($url);

        // If the API call fails, consider the password as safe
        if ($response === false) {
            return false; // If API fails, consider the password as safe.
        }

        // Check if the password suffix is in the response
        foreach (explode("\n", $response) as $line) {
            list($hash_suffix, $count) = explode(':', $line); // Separate hash suffix and count
            // If the suffix matches, the password is compromised
            if ($hash_suffix === $suffix) {
                return true; // The password has been pwned
            }
        }

        return false; // The password is safe
    }

    /**
     * Retrieves the user ID by username.
     *
     * @param string $username The username to search for
     * @return int|null The user ID or null if not found
     */
    private function get_user_id_by_username($username)
    {
        // Prepare the SQL query to fetch the user ID
        $username_cleaned = $this->db->sql_escape(utf8_clean_string($username));
        $sql = 'SELECT user_id FROM ' . USERS_TABLE . ' WHERE username_clean = "' . $username_cleaned . '" LIMIT 1;'
        // Execute the SQL query
        $result = $this->db->sql_query($sql);

        // Fetch the result row
        $row = $this->db->sql_fetchrow($result);
        // Free the result to prevent memory leaks
        $this->db->sql_freeresult($result);

        // Return the user ID if found, or null
        return isset($row['user_id']) ? (int)$row['user_id'] : null;
    }

    /**
     * Forces a password change for the user by updating the password change timestamp.
     *
     * @param int $user_id The user ID for which to force a password change
     */
    private function force_password_change($user_id)
    {
        // Prepare the SQL query to update the user password change timestamp
        $sql = 'UPDATE ' . USERS_TABLE . "
            SET user_passchg = 1541019028
            WHERE user_id = " . (int)$user_id;

        // Execute the SQL query to apply the change
        $this->db->sql_query($sql);
    }
}
