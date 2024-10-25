<?php
/**
*
* @package phpBB Extension - Pwned Passwords Check
* @copyright (c) 2024 @TenGbps
* @license http://opensource.org/licenses/gpl-2.0.php GNU General Public License v2
*
*/

// Prevent direct access to the file
if (!defined('IN_PHPBB'))
{
    exit;
}

// Initialize the $lang array if it is not set or is not an array
if (empty($lang) || !is_array($lang))
{
    $lang = array();
}

// Define language strings for Franch
$lang = array_merge($lang, array(
    'PASSWORD_BREACHED' => 'Votre mot de passe a été trouvé dans une fuite de données. Veuillez utiliser un autre mot de passe pour votre compte.',
));
