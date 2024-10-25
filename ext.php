<?php
/**
*
* @package phpBB Extension - Pwned Passwords Check
* @copyright (c) 2024 @TenGbps
* @license http://opensource.org/licenses/gpl-2.0.php GNU General Public License v2
*
*/

namespace tengbps\pwnedpasswordscheck;

class ext extends \phpbb\extension\base
{
        public function is_enableable()
        {
                $enableable = phpbb_version_compare(PHPBB_VERSION, '3.2', '>=');
                if (!$enableable)
                {
                        $user = $this->container->get('user');
                }

                return true;
        }
}
