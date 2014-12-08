<?php
/**
 * Auto Front-end login to authorize front-end user based on back-end session
 * Authorization process detect back-end session and change currrent PHP session object
 * by loading JUser details to 'user' field. Plugin works only on front-end to avoid session duplicates.
 * Using onAfterInitialise() trigger gives sure that front-end session already exists (as guest) so it may be
 * easily transform into front-end sesssion without creating new session record.
 *
 * @package     plg_system_autofrontendlogin
 * @subpackage  back-end
 * @author      Bartłomiej Krztuk <bartlomiej.krztuk@gmail..com.pl>    
 * @copyright   Copyright (C) 2014 Bartlomiej Krztuk. All rights reserved.
 * @license     http://www.gnu.org/licenses/gpl-2.0.html GNU/GPL
 */

defined('_JEXEC') or die('Restricted access'); 
jimport('joomla.plugin.plugin');

class plgSystemAutoFrontEndLogin extends JPlugin {

	protected $app;

	public function onAfterInitialise() {
		
		if (!$this->app) {
			$this->app = JFactory::getApplication();
		}
		// work only on front-end
		if ($this->app->isAdmin()){  return; }
		// Check for a cookie if user is not logged in (quest cookie)
		if (JFactory::getUser()->get('guest')){
			$config = JFactory::getConfig();
			$cookie_domain = $config->get('cookie_domain', '');
			$cookie_path = $config->get('cookie_path', '/');
			// prepare cookie name
			$cookie_name = md5(JApplicationHelper::getHash('administrator'));
			if($_COOKIE[$cookie_name] !== '') {
				$sessionId = $_COOKIE[$cookie_name];
				// find back-end session
				$db = JFactory::getDbo();
				$query = $db->getQuery(true)
				    ->select($db->quoteName(array('session_id', 'client_id', 'guest', 'time', 'data', 'userid', 'username')))
				    ->from($db->quoteName('#__session'))
				    ->where($db->quoteName('session_id') . ' = '. $db->quote($sessionId))
				    ->order('client_id ASC');
				$db->setQuery($query);
				$adminSession = $db->loadObjectList();
				
				// second check if the session exists but it was changed to guest session (login -> logout)
				preg_match('/"guest";i:(\d)/mis', $adminSession[0]->data, $guest);
				if(count($adminSession) > 0 && !$guest[1]){
					$adminSession = $adminSession[0];
					// user is already logged to back-end
					$session = JFactory::getSession();
					// Update the user related fields for the Joomla sessions table.
					$query = $db->getQuery(true)
						->update($db->quoteName('#__session'))
						->set($db->quoteName('client_id') . ' = ' . '0')
						->set($db->quoteName('guest') . ' = ' . '0')
						->set($db->quoteName('data') . ' = ' . $db->quote($adminSession->data))
						->set($db->quoteName('username') . ' = ' . $db->quote($adminSession->username))
						->set($db->quoteName('userid') . ' = ' . (int) $adminSession->userid)
						->where($db->quoteName('session_id') . ' = ' . $db->quote($session->getId()));
					$res = $db->setQuery($query)->execute();
					
					if($res) {
						// find user ID in back-end session 'data' string
						preg_match('/("id";s:\d*:)"(\w*)"/mis', $adminSession->data, $matches);
						$userId = $matches[2];
						$user = JUser::getInstance($userId);
						$_SESSION['__default']['user'] = $user;
						$this->app->enqueueMessage(JText::_('You\'ve been automatically logged based on your administrator area session. To logout please firstly log out via back-end'), 'message');
					} else {
						$this->app->enqueueMessage(JText::_('Back-end session found but can\t auhorize user.'), 'notice');
					}
				} else {
					// session not found; return 
					return;
				}
			} else {
				return;
			}
		} else {
			// logged user
			return;
		}
	}
}