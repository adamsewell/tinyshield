<?php
/*
Plugin Name: tinyShield - Simple. Focused. Security.
Version: 0.2.8
Description: tinyShield is a security plugin that utilizes real time blacklists and also crowd sources attacker data for enhanced protection.
Plugin URI: https://tinyshield.me
Author: tinyShield.me
Author URI: https://tinyshield.me

	This plugin is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 2 of the License, or
	(at your option) any later version.

	This plugin is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this plugin.  If not, see <http://www.gnu.org/licenses/>.
*/
if(!defined('ABSPATH')) die();

include_once(plugin_dir_path(__FILE__) . 'lib/blacklist_tables.php');
include_once(plugin_dir_path(__FILE__) . 'lib/whitelist_tables.php');
include_once(plugin_dir_path(__FILE__) . 'lib/activity_log_tables.php');
include_once(plugin_dir_path(__FILE__) . 'lib/perm_whitelist_tables.php');
include_once(plugin_dir_path(__FILE__) . 'lib/perm_blacklist_tables.php');

class tinyShield{

	private static $tinyshield_report_url = 'https://endpoint.tinyshield.me/report';
	private static $tinyshield_check_url = 'https://endpoint.tinyshield.me/checkv2';
	private static $tinyshield_upgrade_url = 'https://tinyshield.me/upgrade-my-site/';
	private static $tinyshield_activation_url = 'https://endpoint.tinyshield.me/activatev2';

	public function __construct(){
		register_activation_hook(__FILE__, 'tinyShield::on_activation');

		add_action('admin_menu', 'tinyShield::add_menu');
		add_action('admin_notices', 'tinyShield::notices');
		add_action('admin_init', 'tinyShield::update_options');

		//hook to process incoming connections
		add_action('plugins_loaded', 'tinyShield::on_plugins_loaded', 0);

		//hook to process outgoing connections through the WordPress API
		add_filter('pre_http_request', 'tinyShield::outgoing_maybe_block', 10, 3);

		//hook into the failed login attempts and report back
		add_filter('wp_login_failed', 'tinyShield::log_failed_login');

		//hook into the redirect_canonical filter to detect user enumeration
		add_filter('redirect_canonical', 'tinyShield::log_user_enumeration', 10, 2);

	}

	public static function notices(){
		$options = get_option('tinyshield_options');
?>
		<?php if(empty($options['site_activation_key'])): ?>
			<div class="update-nag"><p><strong><?php _e('tinyShield: tinyShield is not currently activated. Before we can help protect your site, you must register your site. You can do that here <a href="' . admin_url('admin.php?page=tinyshield.php&tab=settings') . '">tinyShield Settings</a> under Site Activation.', 'tinyshield');?></strong></p></div>
		<?php endif; ?>

		<?php if($options['tinyshield_disabled']): ?>
			<div class="update-nag"><p><strong><?php _e('tinyShield: tinyShield is currently disabled and not protecting your site. To re-enable tinyShield, you can do that under the options here <a href="' . admin_url('admin.php?page=tinyshield.php&tab=settings') . '">tinyShield Settings</a> under Options.', 'tinyshield');?></strong></p></div>
		<?php endif; ?>
<?php
	}

	public static function add_menu(){
		if(function_exists('add_menu_page')){
			add_menu_page('tinyShield', 'tinyShield', 'manage_options', basename(__FILE__), 'tinyShield::display_options', plugin_dir_url(__FILE__) . 'img/tinyshield.png');
		}
	}

	public static function update_options(){
		$options = get_option('tinyshield_options');
		$cached_perm_blacklist = get_option('tinyshield_cached_perm_blacklist');

		$default_options = array(
			'report_failed_logins' => true,
			'report_user_enumeration' => true,
			'block_top_countries' => false,
			'tinyshield_disabled' => false
		);

		if(empty($options)){
			update_option('tinyshield_options', $default_options);
		}else{
			$merged_options = $options + $default_options;
			update_option('tinyshield_options', $merged_options);
		}

		if(!is_array($cached_perm_blacklist)){
			$cached_perm_blacklist = array();
			update_option('tinyshield_cached_perm_blacklist', $cached_perm_blacklist);
		}
	}

	public static function on_activation(){
		if(!current_user_can('activate_plugins')){
			_e('You are not authorized to perform this operation.', 'tinyshield');
			die();
		}

		$cached_blacklist = get_option('tinyshield_cached_blacklist');
		$cached_whitelist = get_option('tinyshield_cached_whitelist');
		$cached_perm_whitelist = get_option('tinyshield_cached_perm_whitelist');
		$cached_perm_blacklist = get_option('tinyshield_cached_perm_blacklist');

		self::update_options();

		if(!is_array($cached_blacklist)){
			$cached_blacklist = array();
			update_option('tinyshield_cached_blacklist', $cached_blacklist);
		}

		if(!is_array($cached_perm_blacklist)){
			$cached_perm_blacklist = array();
			update_option('tinyshield_cached_perm_blacklist', $cached_perm_blacklist);
		}

		if(!is_array($cached_perm_whitelist)){
			$cached_perm_whitelist = array();

			$perm_whitelist_entry = new stdClass();
			$perm_whitelist_entry->expires = strtotime('+30 years', current_time('timestamp'));

			$cached_perm_whitelist[ip2long(self::get_valid_ip())] = json_encode($perm_whitelist_entry);
			update_option('tinyshield_cached_perm_whitelist', $cached_perm_whitelist);
		}

		if(!is_array($cached_whitelist)){
			$cached_whitelist = array();
			update_option('tinyshield_cached_whitelist', $cached_whitelist);
		}
	}

	public static function outgoing_maybe_block($pre, $args, $url){
		$options = get_option('tinyshield_options');

		if(empty($url) || !$host = parse_url($url, PHP_URL_HOST) || $options['tinyshield_disabled']){
			return $pre;
		}

		//bypass known good hosts
		$whitelisted_domains = array(
			'endpoint.tinyshield.me',
			'api.wordpress.org',
			parse_url(get_bloginfo('url'), PHP_URL_HOST)
		);

		if(in_array($host, $whitelisted_domains)){
			return $pre;
		}

		$ip = gethostbyname($host);
		$cached_blacklist = get_option('tinyshield_cached_blacklist');

		if(!empty($cached_blacklist) && array_key_exists(ip2long($ip), $cached_blacklist)){
			$blacklist_data = json_decode($cached_blacklist[ip2long($ip)]);
			$blacklist_data->last_attempt = current_time('timestamp');

			$cached_blacklist[ip2long($ip)] = json_encode($blacklist_data);
			update_option('tinyshield_cached_blacklist', $cached_blacklist);

			return true;
		}

		if($result = self::check_ip($ip, 'outbound', $host)){
			self::write_log('tinyShield: outbound remote blacklist lookup: ' . $ip);

			return true;
		}


		return $pre;
	}

	/**
	 * Trigger when all plugins are loaded
	 *
	 * @return void
	 *
	 * @access public
	 * @static
	 */
	public static function on_plugins_loaded() {
		$options = get_option('tinyshield_options');

		if(!$options['tinyshield_disabled'] && self::incoming_maybe_block()){
			status_header(403);
			nocache_headers();
			exit;
		}
	}

	public static function incoming_maybe_block(){
		$ip = self::get_valid_ip();

		self::clean_up_lists();

		//check if valid ip and check the local whitelist
		if($ip && !is_user_logged_in()){

			//check local perm whitelist
			$cached_perm_whitelist = get_option('tinyshield_cached_perm_whitelist');
			if(!empty($cached_perm_whitelist) && array_key_exists(ip2long($ip), $cached_perm_whitelist)){
				self::write_log('tinyShield: incoming ip found in local perm whitelist and was allowed: ' . $ip);
				return false;
			}

			//check local perm blacklist
			$cached_perm_blacklist = get_option('tinyshield_cached_perm_blacklist');
			if(!empty($cached_perm_blacklist) && array_key_exists(ip2long($ip), $cached_perm_blacklist)){
				self::write_log('tinyShield: incoming ip found in local perm blacklist and was blocked: ' . $ip);
				return true;
			}

			//check local cached whitelist
			$cached_whitelist = get_option('tinyshield_cached_whitelist');
			if(!empty($cached_whitelist) && array_key_exists(ip2long($ip), $cached_whitelist)){

				$data = json_decode($cached_whitelist[ip2long($ip)]);
				$data->last_attempt = current_time('timestamp');

				$cached_whitelist[ip2long($ip)] = json_encode($data);
				update_option('tinyshield_cached_whitelist', $cached_whitelist);

				self::write_log('tinyShield: incoming ip found in local whitelist and was allowed: ' . $ip);
				return false;
			}

			//check local cached blacklist
			$cached_blacklist = get_option('tinyshield_cached_blacklist');
			if(!empty($cached_blacklist) && array_key_exists(ip2long($ip), $cached_blacklist)){

				$blacklist_data = json_decode($cached_blacklist[ip2long($ip)]);
				$blacklist_data->last_attempt = current_time('timestamp');
				$cached_blacklist[ip2long($ip)] = json_encode($blacklist_data);
				update_option('tinyshield_cached_blacklist', $cached_blacklist);

				self::write_log('tinyShield: ip blocked from local cached blacklist: ' . $ip);
				$maybe_blocked = true;
			}

			//ip does not exist locally at all, remote lookup needed
			if(self::check_ip($ip)){
				self::write_log('tinyShield: incoming remote blacklist lookup: ' . $ip);
				$maybe_blocked = true;
			}
		}

		return false; //default allow (failopen)
	}

	private static function check_ip($ip, $direction = 'inbound', $domain = ''){
		$options = get_option('tinyshield_options');
		$cached_blacklist = get_option('tinyshield_cached_blacklist');
		$cached_whitelist = get_option('tinyshield_cached_whitelist');

		$response = wp_remote_post(
			self::$tinyshield_check_url . '/' . ip2long($ip),
			array(
				'body' => array(
					'activation_key' => urlencode($options['site_activation_key']),
					'requesting_site' => urlencode(site_url()),
					// 'block_top_countries' => urlencode($options['block_top_countries'])
				)
			)
		);

		$response_code = wp_remote_retrieve_response_code($response);
		$response_body = wp_remote_retrieve_body($response);

		if(!is_wp_error($response)){
			self::write_log('tinyShield: blacklist lookup response');
			self::write_log($response_body);
			self::write_log($response_code);

			if(!empty($response_body)){

				$list_data = json_decode($response_body);
				$list_data->last_attempt = current_time('timestamp');

				if($list_data->action == 'block'){
					$list_data->expires = strtotime('+24 hours', current_time('timestamp'));
					$list_data->direction = $direction;
					if($domain){
						$list_data->called_domain = $domain;
					}
					$cached_blacklist[ip2long($ip)] = json_encode($list_data);
					update_option('tinyshield_cached_blacklist', $cached_blacklist);
					return true;
				}elseif($list_data->action == 'allow'){
					$list_data->expires = strtotime('+1 hour', current_time('timestamp'));
					$list_data->direction = $direction;
					if($domain){
						$list_data->called_domain = $domain;
					}
					$cached_whitelist[ip2long($ip)] = json_encode($list_data);

					update_option('tinyshield_cached_whitelist', $cached_whitelist);
					return false;
				}

				return false; //default to allow in case of emergency
			}
		}else{
			self::write_log('tinyShield: check_ip error');
			self::write_log($response->get_error_message());
		}
	}

	private static function clean_up_lists(){
		$cached_blacklist = get_option('tinyshield_cached_blacklist');
		$cached_whitelist = get_option('tinyshield_cached_whitelist');

		foreach($cached_blacklist as $iphash => $iphash_data){
			$iphash_data = json_decode($iphash_data);

			if($iphash_data->expires < current_time('timestamp')){
				unset($cached_blacklist[$iphash]);
			}
		}

		foreach($cached_whitelist as $iphash => $iphash_data){
			$iphash_data = json_decode($iphash_data);

			if($iphash_data->expires < current_time('timestamp')){
				unset($cached_whitelist[$iphash]);
			}
		}

		update_option('tinyshield_cached_whitelist', $cached_whitelist);
		update_option('tinyshield_cached_blacklist', $cached_blacklist);
	}

	private static function get_valid_ip(){
		if(filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)){
			return $_SERVER['REMOTE_ADDR'];
		}

		return false;
	}

	private static function write_log($log){
		if(true === WP_DEBUG){
			if(is_array($log) || is_object($log)){
				error_log(print_r($log, true));
			}else{
				error_log($log);
			}
		}
	}

	private static function activate_site($registration_data){
		$return = wp_remote_post(
			self::$tinyshield_activation_url,
			array(
				'body' => array(
					'fname' => $registration_data['fname'],
					'lname' => $registration_data['lname'],
					'email' => $registration_data['email'],
					'association_key' => $registration_data['association_key'],
					'site' => $registration_data['site'],
					'action' => 'activate'
				)
			)
		);


		if(is_wp_error($return) || wp_remote_retrieve_response_code($return) != 200){
			return false;
		}

		$response = json_decode(wp_remote_retrieve_body($return));

		if(!empty($response->message) && $response->message == 'activated'){
			return $response;
		}elseif(!empty($response->message)){
			return sanitize_text_field($response->message);
		}else{
			return false;
		}

	}

	private static function deactivate_site($registration_data){
		$return = wp_remote_post(
			self::$tinyshield_activation_url,
			array(
				'body' => array(
					'site' => $registration_data['site'],
					'action' => 'deactivate',
					'activation_key' => $registration_data['activation_key']
				)
			)
		);

		if(is_wp_error($return) || wp_remote_retrieve_response_code($return) != 200){
			return false;
		}

		if(wp_remote_retrieve_body($return) == 'site_key_deactivated'){
			return true;
		}

		return sanitize_text_field(wp_remote_retrieve_body($return));

	}

	public static function log_user_enumeration($redirect, $request){
		$options = get_option('tinyshield_options');

		if(!is_admin() && preg_match('/author=([0-9]*)/i', $request) && $options['report_user_enumeration']){
			$remote_ip = self::get_valid_ip();
			$response = wp_remote_post(
				self::$tinyshield_report_url,
				array(
					'body' => array(
						'ip_to_report' => $remote_ip,
						'type' => 'user_enumeration',
						'reporting_site' => site_url(),
						'time_of_occurance' => current_time('timestamp')
					)
				)
			);
		}

		return $redirect;
	}

	public static function log_failed_login($username){
		$options = get_option('tinyshield_options');

		if($options['report_failed_logins']){
			$remote_ip = self::get_valid_ip();
			if($remote_ip){
				$response = wp_remote_post(
					self::$tinyshield_report_url,
					array(
						'body' => array(
							'ip_to_report' => $remote_ip,
							'type' => 'failed_logins',
							'username_tried' => $username,
							'reporting_site' => site_url(),
							'time_of_occurance' => current_time('timestamp')
						)
					)
				);
			}
		}
	}

	public static function log_block_user_enumeration($query){
		if(!is_admin()){
			$remote_ip = self::get_valid_ip();

			if(preg_match('/\?author=([0-9]*)(\/*)/i', $request)){
				var_dump($request);
				die();
			}
		}
	}

	public static function display_options(){
		if(!current_user_can('manage_options')){
			_e('You are not authorized to perform this operation.', 'tinyshield');
			die();
		}

		$options = get_option('tinyshield_options');
		$cached_blacklist = get_option('tinyshield_cached_blacklist');
		$cached_whitelist = get_option('tinyshield_cached_whitelist');
		$cached_perm_whitelist = get_option('tinyshield_cached_perm_whitelist');
		$cached_perm_blacklist = get_option('tinyshield_cached_perm_blacklist');

		$errors = '';
		$alerts = '';

		$success_messages = array(
			'site_key_activated' => __('Your site is now activated!', 'tinyshield'),
			'site_key_deactivated' => __('Site Key Deactivated', 'tinyshield'),
			'settings_updated' => 'Settings Updated',
			'blacklist_cleared' => 'Local Blacklist Has Been Cleared',
			'whitelist_cleared' => 'Local Whitelist Has Been Cleared',
			'reported_false_positive' => 'Your report has been logged. Thanks for reporting, we\'ll check it out!'
		);

		$error_messages = array(
			'key_not_found' => __('Sorry, this key was not found. Please try again.', 'tinyshield'),
			'key_in_use' => __('Sorry, this site has already been activated. Please contact support.', 'tinyshield'),
			'key_expired' => 'This key is expired. Please renew your key.',
			'key_banned' => 'This key has been banned.',
			'something_went_wrong' => 'Something went wrong but we\'re not sure what...',
			'missing_registration_data' => 'You must provide your first name, last name, and email address to register your site.'
		);

		/*****************************************
				Settings Page Update
		*****************************************/
		if(isset($_POST['tinyshield_save_options']) && $_POST['tinyshield_action'] == 'options_save' && wp_verify_nonce($_POST['_wpnonce'], 'tinyshield-update-options')) {
			if(is_array($_POST['options']) && !empty($_POST['options'])){
				foreach($options as $key => $value){
					if(array_key_exists($key, $_POST['options'])){
						$options[$key] = filter_var($_POST['options'][$key], FILTER_VALIDATE_BOOLEAN);
					}elseif(is_bool($value) && $value){
						$options[$key] = false;
					}elseif(is_null($value)){
						$options[$key] = false;
					}
				}
			}

			update_option('tinyshield_options', $options);
			$alerts = $success_messages['settings_updated'];
		}

		/*****************************************
			Handle activating site
		*****************************************/
		if(isset($_POST['tinyshield_action']) && $_POST['tinyshield_action'] == 'activate-site' && wp_verify_nonce($_POST['_wpnonce'], 'tinyshield-activate-site')){

			if(!empty($_POST['activate']['fname']) && !empty($_POST['activate']['lname']) && !empty($_POST['activate']['email'])){
				$registration_data = array(
					'action' => 'activate',
					'fname' => sanitize_text_field($_POST['activate']['fname']),
					'lname' => sanitize_text_field($_POST['activate']['lname']),
					'email' => sanitize_text_field($_POST['activate']['email']),
					'association_key' => sanitize_text_field($_POST['activate']['association_key']),
					'site' => esc_attr($_POST['activate']['site'])
				);

				$maybe_activate = self::activate_site($registration_data);

				if(!empty($maybe_activate->message) && $maybe_activate->message == 'activated'){
					$options['site_activation_key'] = $maybe_activate->activation_key;
					update_option('tinyshield_options', $options);
					$alerts = $success_messages['site_key_activated'];
				}else{
					$errors = $error_messages[$maybe_activate];
				}
			}else{
				$errors = $error_messages['missing_registration_data'];
			}

		}

		/*****************************************
			Handle deactivating site
		*****************************************/
		if(isset($_POST['tinyshield_action']) && $_POST['tinyshield_action'] == 'deactivate-site' && wp_verify_nonce($_POST['_wpnonce'], 'tinyshield-deactivate-site')){
			$registration_data = array(
				'action' => 'deactivate',
				'site' => esc_attr(site_url()),
				'activation_key' => $options['site_activation_key']
			);

			$maybe_deactivate = self::deactivate_site($registration_data);

			if(is_bool($maybe_deactivate) && $maybe_deactivate){
				$options['site_activation_key'] = '';
				update_option('tinyshield_options', $options);
				$alerts = $success_messages['site_key_deactivated'];

			}else{
				$errors = $error_messages[$maybe_deactivate];
			}
		}

		/*****************************************
			Handle clearing of local blacklist
		*****************************************/
		if(isset($_POST['tinyshield_action']) && $_POST['tinyshield_action'] == 'clear_cached_blacklist' && wp_verify_nonce($_POST['_wpnonce'], 'tinyshield-clear-local-blacklist')){
			$cached_blacklist = array();
			update_option('tinyshield_cached_blacklist', $cached_blacklist);

			$alerts = $success_messages['blacklist_cleared'];
		}

		/*****************************************
			Handle clearing of local whitelist
		*****************************************/
		if(isset($_POST['tinyshield_action']) && $_POST['tinyshield_action'] == 'clear_cached_whitelist' && wp_verify_nonce($_POST['_wpnonce'], 'tinyshield-clear-local-whitelist')){
			$cached_whitelist = array();
			update_option('tinyshield_cached_whitelist', $cached_whitelist);

			$alerts = $success_messages['whitelist_cleared'];
		}

		/*****************************************
			Handle Reporting of False Positives
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'report_false_positive' && is_numeric($_GET['iphash']) && wp_verify_nonce($_GET['_wpnonce'], 'tinyshield-report-false-positive')){
			if(absint($_GET['iphash'])){
				$response = wp_remote_post(
					self::$tinyshield_report_url,
					array(
						'body' => array(
							'ip_to_report' => long2ip($_GET['iphash']),
							'type' => 'report_false_positive',
							'reporting_site' => site_url(),
							'time_of_occurance' => current_time('timestamp')
						)
					)
				);

				if(!is_wp_error($response) && wp_remote_retrieve_response_code($response) == 200){
					$alerts = $success_messages['reported_false_positive'];
				}else{
					$errors = $error_messages['something_went_wrong'];
				}
			}
		}

		/*****************************************
			Add Custom IP to Permanent Whitelist Action
		******************************************/
		if(isset($_POST['tinyshield_perm_whitelist_update']) && wp_verify_nonce($_POST['_wpnonce'], 'update-tinyshield-perm-whitelist') && !empty($_POST['perm_ip_to_whitelist'])){
				$ips = array_filter(array_map('trim', explode("\r\n", $_POST['perm_ip_to_whitelist'])));

				foreach($ips as $ip){
					if(!empty($ip) && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)){
						$perm_whitelist_entry = new stdClass();
						$perm_whitelist_entry->expires = strtotime('+30 years', current_time('timestamp'));
						$cached_perm_whitelist[ip2long($ip)] = json_encode($perm_whitelist_entry);
					}else{
						$invalid_ip = true;
					}
				}

				if($invalid_ip){
?>
					<div class="error"><p><strong><?php _e('Invalid IP detected. Please ensure all IP addresses are valid.', "tinyshield");?></strong></p></div>
<?php
				}else{
					update_option('tinyshield_cached_perm_whitelist', $cached_perm_whitelist);
?>
					<div class="updated"><p><strong><?php _e('IP Address has been added to the Permanent Whitelist', "tinyshield");?></strong></p></div>
<?php
				}
		}

		/*****************************************
			Add Custom IP to Permanent Blacklist Action
		******************************************/
		if(isset($_POST['tinyshield_perm_blacklist_update']) && wp_verify_nonce($_POST['_wpnonce'], 'update-tinyshield-perm-blacklist') && !empty($_POST['perm_ip_to_blacklist'])){
				$ips = array_filter(array_map('trim', explode("\r\n", $_POST['perm_ip_to_blacklist'])));

				foreach($ips as $ip){
					if(!empty($ip) && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)){
						$perm_blacklist_entry = new stdClass();
						$perm_blacklist_entry->expires = strtotime('+30 years', current_time('timestamp'));
						$cached_perm_blacklist[ip2long($ip)] = json_encode($perm_blacklist_entry);

						if(array_key_exists(ip2long($ip), $cached_whitelist)){
							unset($cached_whitelist[ip2long($ip)]);
						}

					}else{
						$invalid_ip = true;
					}
				}

				if(isset($invalid_ip) && $invalid_ip){
?>
					<div class="error"><p><strong><?php _e('Invalid IP detected. Please ensure all IP addresses are valid.', "tinyshield");?></strong></p></div>
<?php
				}else{
					update_option('tinyshield_cached_whitelist', $cached_whitelist);
					update_option('tinyshield_cached_perm_blacklist', $cached_perm_blacklist);
?>
					<div class="updated"><p><strong><?php _e('IP Address has been added to the Permanent Blacklist', "tinyshield");?></strong></p></div>
<?php
				}
		}

		/*****************************************
		 	Delete Perm Blacklist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'delete-perm-blacklist' && is_numeric($_GET['iphash']) && wp_verify_nonce($_GET['_wpnonce'], 'delete-tinyshield-perm-blacklist-item')){
			unset($cached_perm_blacklist[$_GET['iphash']]);
			update_option('tinyshield_cached_perm_blacklist', $cached_perm_blacklist);
?>
			<div class="updated"><p><strong><?php _e('IP Address has been removed from the Permanent Blacklist', "tinyshield");?></strong></p></div>
<?php
		}

		/*****************************************
		 	Delete Perm Whitelist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'delete-perm-whitelist' && is_numeric($_GET['iphash']) && wp_verify_nonce($_GET['_wpnonce'], 'delete-tinyshield-perm-whitelist-item')){
			unset($cached_perm_whitelist[$_GET['iphash']]);
			update_option('tinyshield_cached_perm_whitelist', $cached_perm_whitelist);
?>
			<div class="updated"><p><strong><?php _e('IP Address has been removed from the Permanent Whitelist', "tinyshield");?></strong></p></div>
<?php
		}

		/*****************************************
		 	Move to Blacklist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'add_to_blacklist' && is_numeric($_GET['iphash']) && wp_verify_nonce($_GET['_wpnonce'], 'tinyshield-move-item-blacklist')){
			$new_bl_item = json_decode($cached_whitelist[$_GET['iphash']]);
			$new_bl_item->action = 'block';
			$new_bl_item->date_added = current_time('timestamp');
			$new_bl_item->expires = strtotime('+24 hours', current_time('timestamp'));

			$cached_blacklist[$_GET['iphash']] = json_encode($new_bl_item);

			unset($cached_whitelist[$_GET['iphash']]);

			update_option('tinyshield_cached_whitelist', $cached_whitelist);
			update_option('tinyshield_cached_blacklist', $cached_blacklist);
?>
			<div class="updated"><p><strong><?php _e('The IP Address has been placed in the Blacklist for 24 hours.', "tinyshield");?></strong></p></div>
<?php
		}

		/*****************************************
		 	Move to Perm Whitelist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'add_to_perm_whitelist' && is_numeric($_GET['iphash']) && wp_verify_nonce($_GET['_wpnonce'], 'tinyshield-move-item-perm-whitelist')){
			$cached_perm_whitelist[$_GET['iphash']] = strtotime('+30 years', current_time('timestamp'));
			unset($cached_blacklist[$_GET['iphash']]);
			unset($cached_whitelist[$_GET['iphash']]);

			update_option('tinyshield_cached_perm_whitelist', $cached_perm_whitelist);
			update_option('tinyshield_cached_whitelist', $cached_whitelist);
			update_option('tinyshield_cached_blacklist', $cached_blacklist);
?>
			<div class="updated"><p><strong><?php _e('The IP Address has been placed in the Permanent Whitelist.', "tinyshield");?></strong></p></div>
<?php
		}

		/*****************************************
			Delete IP Address from Blacklist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'remove_from_blacklist' && is_numeric($_GET['iphash']) && wp_verify_nonce($_GET['_wpnonce'], 'tinyshield-delete-blacklist-item')){
			unset($cached_blacklist[$_GET['iphash']]);
			update_option('tinyshield_cached_blacklist', $cached_blacklist);
?>
			<div class="updated"><p><strong><?php _e('The IP Address has been removed from the Blacklist. If this IP is trys to connect to your site again, it will be rechecked.', "tinyshield");?></strong></p></div>
<?php
		}

		/*****************************************
			Move to Whitelist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'add_to_whitelist' && is_numeric($_GET['iphash']) && wp_verify_nonce($_GET['_wpnonce'], 'tinyshield-move-item-whitelist')){
			$new_wl_item = json_decode($cached_blacklist[$_GET['iphash']]);
			$new_wl_item->action = 'allow';
			$new_wl_item->date_added = current_time('timestamp');
			$new_wl_item->expires = strtotime('+1 hour', current_time('timestamp'));

			$cached_whitelist[$_GET['iphash']] = json_encode($new_wl_item);

			unset($cached_blacklist[$_GET['iphash']]);
			update_option('tinyshield_cached_whitelist', $cached_whitelist);
			update_option('tinyshield_cached_blacklist', $cached_blacklist);

?>
			<div class="updated"><p><strong><?php _e('The IP Address has added to the Whitelist.', "tinyshield");?></strong></p></div>
<?php
		}

		/*****************************************
			Delete IP Address from Whitelist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'remove_from_whitelist' && is_numeric($_GET['iphash']) && wp_verify_nonce($_GET['_wpnonce'], 'tinyshield-delete-whitelist-item')){
			unset($cached_whitelist[$_GET['iphash']]);
			update_option('tinyshield_cached_whitelist', $cached_whitelist);
?>
			<div class="updated"><p><strong><?php _e('The IP Address has been removed from the Blacklist. If this IP is trys to connect to your site again, it will be rechecked.', "tinyshield");?></strong></p></div>
<?php
		}

		if(!empty($alerts)){
?>
			<div class="updated"><p><strong><?php esc_attr_e($alerts);?></strong></p></div>
<?php
		}

		if(!empty($errors)){
?>
			<div class="error"><p><strong><?php esc_attr_e($errors); ?></strong></p></div>
<?php
		}

		/*****************************************
			Options Page
		******************************************/
?>
			<div class="wrap">
				<?php $active_tab = isset($_GET['tab']) ? $_GET['tab'] : 'log'; ?>
				<h2> <?php _e('tinyShield - Simple. Focused. Security.', 'tinyshield') ?></h2>
				<h2 class="nav-tab-wrapper">
					<a href="?page=tinyshield.php&tab=log" class="nav-tab <?php echo $active_tab == 'log' ? 'nav-tab-active' : ''; ?>">Activity Log</a>
					<a href="?page=tinyshield.php&tab=perm-whitelist" class="nav-tab <?php echo $active_tab == 'perm-whitelist' ? 'nav-tab-active' : ''; ?>">Permanent Whitelist (<?php echo count($cached_perm_whitelist); ?>)</a>
					<a href="?page=tinyshield.php&tab=perm-blacklist" class="nav-tab <?php echo $active_tab == 'perm-blacklist' ? 'nav-tab-active' : ''; ?>">Permanent Blacklist (<?php echo count($cached_perm_blacklist); ?>)</a>
					<a href="?page=tinyshield.php&tab=whitelist" class="nav-tab <?php echo $active_tab == 'whitelist' ? 'nav-tab-active' : ''; ?>">Whitelist (<?php echo count($cached_whitelist); ?>)</a>
					<a href="?page=tinyshield.php&tab=blacklist" class="nav-tab <?php echo $active_tab == 'blacklist' ? 'nav-tab-active' : ''; ?>">Blacklist (<?php echo count($cached_blacklist); ?>)</a>
					<a href="?page=tinyshield.php&tab=settings" class="nav-tab <?php echo $active_tab == 'settings' ? 'nav-tab-active' : ''; ?>">Settings</a>
				</h2>

				<!--
						**********************************
						 activity log
						**********************************
				-->

				<?php if($active_tab == 'log'): ?>
					<form method="post" action="<?php echo esc_attr($_SERVER['REQUEST_URI']); ?>">
						<h3>Activity Log</h3>
						<p>View the latest traffic to your site and how it was dealt with by tinyShield. Reporting a false positive will submit the offending IP to tinyShield for further review.</p>
						<hr />
					</form>
					<?php
						$tinyShield_ActivityLog_Table = new tinyShield_ActivityLog_Table();
						$tinyShield_ActivityLog_Table->prepare_items();
					?>
					<form id="activity-log-table" method="get">
						<input type="hidden" name="page" value="<?php echo absint($_REQUEST['page']); ?>" />
						<?php $tinyShield_ActivityLog_Table->display(); ?>
					</form>
				<?php endif; ?>

				<!--
						**********************************
							settings
						**********************************
				-->

				<?php if($active_tab == 'settings'): ?>
						<h2 class="title"><?php _e('Site Activation', 'tinyshield'); ?></h2>
						<h3><?php _e('Activation Key', 'tinyshield'); ?></h3>

						<form method="post" action="<?php echo esc_attr($_SERVER['REQUEST_URI']); ?>">
							<p>
								<?php if(empty($options['site_activation_key'])): ?>
									<p>Before we can help protect your site, you must register and activate your site with tinyShield.</p>
									<?php wp_nonce_field('tinyshield-activate-site'); ?>
									<input type="hidden" name="tinyshield_action" value="activate-site" />

									<p>
										<input size="28" type="text" placeholder="<?php _e('Contact First Name', 'tinyshield'); ?>" name="activate[fname]" value="" />
										<input size="28" type="text" placeholder="<?php _e('Contact Last Name', 'tinyshield'); ?>" name="activate[lname]" value="" />
									</p>
									<p><input size="56" type="text" placeholder="<?php _e('Contact Email Address', 'tinyshield'); ?>" name="activate[email]" value="" /></p>
									<p><input size="56" type="text" placeholder="<?php _e('Site Association Key (For Agencies or Multiple Sites)', 'tinyshield'); ?>" name="activate[association_key]" value="" /></p>

									<input type="hidden" name="activate[site]" value="<?php esc_attr_e(site_url()); ?>" />
									<p><input class="button button-primary" type="submit" name="activate-site" id="activate-site" value="<?php _e('Activate This Site', 'tinyshield'); ?>" /></p>
								<?php else: ?>
									<p><input type="text" size="56" value="<?php _e('Your Site is Currently Activated with tinyShield'); ?>" disabled /> 😎 </p>
									<?php wp_nonce_field('tinyshield-deactivate-site'); ?>
									<input type="hidden" name="tinyshield_action" value="deactivate-site" />
									<p><input class="button button-secondary" type="submit" name="deactivate-site" id="deactivate-site" value="<?php _e('Deactivate This Site', 'tinyshield'); ?>" /></p>

								<?php endif; ?>
							</p>
						</form>

						<?php if(empty($options['site_professional_key']) && !empty($options['site_activation_key'])): ?>
							<h3><?php _e('Upgrade To Professional', 'tinyshield'); ?></h3>
									<p><?php _e('Gain access to the most comprehensive blacklist and whitelist feeds we have to offer by signing up for our Professional service. Not only do you get access to our comprehensive feeds, you also support the project and gain access to premium support. Perfect for professional and commercial sites.', 'tinyshield'); ?></p>
									<p><a target="_blank" href="<?php esc_attr_e(add_query_arg('site_activation_key', $options['site_activation_key'], self::$tinyshield_upgrade_url)); ?>" class="button button-primary"><?php _e('Upgrade This Site', 'tinyshield'); ?></a></p>
						<?php endif; ?>

						<hr />

						<h2 class="title"><?php _e('Options', 'tinyshield'); ?></h2>
						<form method="post" action="<?php echo esc_attr($_SERVER['REQUEST_URI']); ?>">
							<h3><?php _e('Report Failed Logins', 'tinyshield'); ?></h3>
							<p>Toggle this to enable or disable reporting failed logins to tinyShield. <strong>Enabled by default.</strong></p>
							<p><input type="checkbox" name="options[report_failed_logins]" id="options[report_failed_logins]" <?php echo ($options['report_failed_logins']) ? 'checked' : 'unchecked' ?> /> <label for="report_failed_logins"><?php _e('Report Failed Logins?', 'tinyshield'); ?></label></p>

							<h3><?php _e('Report User Enumeration Attempts', 'tinyshield'); ?></h3>
							<p>Toggle this to enable or disable reporting user enumeration attempts to tinyShield. <strong>Enabled by default.</strong></p>
							<p><input type="checkbox" name="options[report_user_enumeration]" id="options[report_user_enumeration]" <?php echo ($options['report_user_enumeration']) ? 'checked' : 'unchecked' ?> /> <label for="report_user_enumeration"><?php _e('Report User Enumeration Attempts?', 'tinyshield'); ?></label></p>

							<!-- <h3><?php _e('Block Top Attacking Countries', 'tinyshield'); ?></h3>
							<p>Toggle this to enable or disable the blocking of top attacking countries. The list includes, but is not limited to China, Russia, Turkey, India, Pakistan, Romania and others. Adheres to permanent whitelist. <strong>Disabled by default.</strong></p>
							<p><input type="checkbox" name="options[block_top_countries]" id="options[block_top_countries]" <?php echo ($options['block_top_countries']) ? 'checked' : 'unchecked' ?> /> <label for="block_top_countries"><?php _e('Block Top Countries?', 'tinyshield'); ?></label></p> -->

							<h3><?php _e('Disable tinyShield', 'tinyshield'); ?></h3>
							<p>Toggle this to enable or disable the core functionality of this plugin. It is <strong>NOT</strong> recommended to disable tinyShield and if you must, do only for testing purposes. <strong>Disabled by default.</strong></p>
							<p><input type="checkbox" name="options[tinyshield_disabled]" id="options[tinyshield_disabled]" <?php echo ($options['tinyshield_disabled']) ? 'checked' : 'unchecked' ?> /> <label for="tinyshield_disabled"><?php _e('Disable tinyShield?', 'tinyshield'); ?></label></p>

							<div class="submit">
								<?php wp_nonce_field('tinyshield-update-options'); ?>
								<input type="hidden" name="tinyshield_action" value="options_save" />
								<input type="submit" class="button button-primary" name="tinyshield_save_options" value="<?php _e('Save Settings', 'tinyshield') ?>" />
							</div>
						</form>

						<hr />

						<h2 class="title"><?php _e('Diagnostics', 'tinyshield'); ?></h2>
						<h3><?php _e('Clear Cached Blacklist', 'tinyshield'); ?></h3>

						<form method="post" action="<?php echo esc_attr($_SERVER['REQUEST_URI']); ?>">
							<p>Use this to clear all addresses from your local cached blacklist. Use only in case of issues.</p>
							<?php wp_nonce_field('tinyshield-clear-local-blacklist'); ?>
							<input type="hidden" name="tinyshield_action" value="clear_cached_blacklist" />
							<p><input class="button button-secondary" type="submit" name="clear_cached_blacklist" id="clear_cached_blacklist" value="<?php _e('Clear Cache Blacklist', 'tinyshield'); ?>" /></p>
						</form>

						<h3><?php _e('Clear Cached Whitelist', 'tinyshield'); ?></h3>

						<form method="post" action="<?php echo esc_attr($_SERVER['REQUEST_URI']); ?>">
							<p>Use this to clear all addresses from your local cached whitelist. Use only in case of issues.</p>
							<?php wp_nonce_field('tinyshield-clear-local-whitelist'); ?>
							<input type="hidden" name="tinyshield_action" value="clear_cached_whitelist" />
							<p><input class="button button-secondary" type="submit" name="clear_cached_whitelist" id="clear_cached_whitelist" value="<?php _e('Clear Cache Whitelist', 'tinyshield'); ?>" /></p>
						</form>

				<?php endif; ?>

				<!--
						**********************************
							permanent blacklist table
						**********************************
				-->
				<?php if($active_tab == 'perm-blacklist'): ?>
					<form method="post" action="<?php echo esc_url(remove_query_arg(array('action', '_wpnonce', 'iphash'), $_SERVER['REQUEST_URI'])); ?>">
						<?php
							if(function_exists('wp_nonce_field')){
								wp_nonce_field('update-tinyshield-perm-blacklist');
								$delete_item_nonce = wp_create_nonce('delete-tinyshield-perm-blacklist-item');
							}
						?>
						<h3>Permanent Blacklist</h3>
						<p>These are addresses that are permanently blocked from accessing the site regardless if they are found in a blacklist or not.</p>
						<hr />
						<p>
							<textarea name="perm_ip_to_blacklist" rows="5" cols="60" placeholder="<?php _e('Enter a single or multiple IP addresses. One address per line.', 'tinyshield'); ?>"></textarea>
						</p>
						<p>
							<input type="submit" class="button button-primary" name="tinyshield_perm_blacklist_update" value="<?php _e('Add to Blacklist', 'tinyshield') ?>" />
						</p>

					</form>
					<?php
						$tinyShield_PermBlackList_Table = new tinyShield_PermBlackList_Table();
						$tinyShield_PermBlackList_Table->prepare_items();
					?>
					<form id="perm-blacklist-table" method="get">
						<input type="hidden" name="page" value="<?php echo absint($_REQUEST['page']); ?>" />
						<?php $tinyShield_PermBlackList_Table->display(); ?>
					</form>
				<?php endif; ?>

				<!--
						**********************************
							permanent whitelist table
						**********************************
				-->

				<?php if($active_tab == 'perm-whitelist'): ?>
					<form method="post" action="<?php echo esc_url(remove_query_arg(array('action', '_wpnonce', 'iphash'), $_SERVER['REQUEST_URI'])); ?>">
						<?php
							if(function_exists('wp_nonce_field')){
								wp_nonce_field('update-tinyshield-perm-whitelist');
								$delete_item_nonce = wp_create_nonce('delete-tinyshield-perm-whitelist-item');
							}
						?>
						<h3>Permanent Whitelist</h3>
						<p>These are addresses that are permanently allowed to access the site even if they are found in a black list. This is useful for false positives. The permanent whitelist is checked before any other check is performed.</p>
						<hr />
						<p>
							<!-- <input type="text" name="perm_ip_to_whitelist" size="36" placeholder="<?php _e('Enter a valid single IP Address...', 'tinyshield'); ?>" value=""> -->
							<textarea name="perm_ip_to_whitelist" rows="5" cols="60" placeholder="<?php _e('Enter a single or multiple IP addresses. One address per line.', 'tinyshield'); ?>"></textarea>
						</p>
						<p>
							<input type="submit" class="button button-primary" name="tinyshield_perm_whitelist_update" value="<?php _e('Add to Whitelist', 'tinyshield') ?>" />
						</p>
					</form>
					<?php
						$tinyShield_PermWhiteList_Table = new tinyShield_PermWhiteList_Table();
						$tinyShield_PermWhiteList_Table->prepare_items();
					?>
					<form id="perm-whitelist-table" method="get">
						<input type="hidden" name="page" value="<?php echo absint($_REQUEST['page']); ?>" />
						<?php $tinyShield_PermWhiteList_Table->display(); ?>
					</form>
			  <?php endif; ?>
				<?php if($active_tab == 'whitelist'): ?>
					<h3>Whitelist</h3>
					<p>These are addresses that have been checked and are not known to be malicious at this time. Addresses will remain cached for 1 hour and then will be checked again.</p>
					<hr />
					<?php
						$tinyShield_WhiteList_Table = new tinyShield_WhiteList_Table();
						$tinyShield_WhiteList_Table->prepare_items();
					?>
					<form id="whitelist-table" method="get">
						<input type="hidden" name="page" value="<?php echo absint($_REQUEST['page']); ?>" />
						<?php $tinyShield_WhiteList_Table->display(); ?>
					</form>
			  <?php endif; ?>
				<!--
						**********************************
							blacklist table
						**********************************
				-->
				<?php if($active_tab == 'blacklist'): ?>
					<h3>Blacklist</h3>
					<p>These are addresses that have tried to visit your site and been found to be malicious. Requests from these addresses are blocked and will remain cached for 24 hours and then will be checked again.</p>
					<hr />
					<?php
						$tinyShield_BlackList_Table = new tinyShield_BlackList_Table();
						$tinyShield_BlackList_Table->prepare_items();
					?>
					<form id="blacklist-table" method="get">
						<input type="hidden" name="page" value="<?php echo absint($_REQUEST['page']); ?>" />
						<?php $tinyShield_BlackList_Table->display(); ?>
					</form>
				<?php endif; ?>

			</div> <!--end div -->
<?php
	}
} //End tinyShield Class

$tinyShield = new tinyShield();
