<?php
/*
Plugin Name: tinyShield - Simple. Focused. Security.
Version: 1.2.0
Description: tinyShield is a fast, effective, realtime, and crowd sourced protection plugin for WordPress. Easily block bots, brute force attempts, exploits and more without bloat.
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

//load our library files
require_once(plugin_dir_path(__FILE__) . 'lib/tables/blocklist_tables.php');
require_once(plugin_dir_path(__FILE__) . 'lib/tables/allowlist_tables.php');
require_once(plugin_dir_path(__FILE__) . 'lib/tables/activity_log_tables.php');
require_once(plugin_dir_path(__FILE__) . 'lib/tables/perm_allowlist_tables.php');
require_once(plugin_dir_path(__FILE__) . 'lib/tables/perm_blocklist_tables.php');
require_once(plugin_dir_path(__FILE__) . 'lib/upgrade/functions.php');
require_once(plugin_dir_path(__FILE__) . 'lib/functions.php');
require_once(plugin_dir_path(__FILE__) . 'lib/admin/admin.php');
require_once(plugin_dir_path(__FILE__) . 'lib/dashboard/widget.php');


//load any additional modules
$modules_dir = trailingslashit(plugin_dir_path(__FILE__) . 'modules');

if(is_dir($modules_dir)){
	foreach(new DirectoryIterator($modules_dir) as $file){
		if(!$file->isDot() && $file->getType() === 'file' && $file->isReadable()){
			require_once($modules_dir . $file->getFilename());
		}
	}
}

class tinyShield{

	public static $tinyshield_report_url = 'https://endpoint.tinyshield.me/report';
	private static $tinyshield_check_url = 'https://endpoint.tinyshield.me/checkv3';
	public static $tinyshield_upgrade_url = 'https://tinyshield.me/checkout/';
	public static $tinyshield_activation_url = 'https://endpoint.tinyshield.me/activatev2';
	public static $tinyshield_account_url = 'https://tinyshield.me/my-account/';
	public static $tinyshield_news_feed = 'https://tinyshield.me/feed/';
	public static $plugin_dir_url = '';
	public static $plugin_basename = '';

	public function __construct(){
		//set static variables
		self::$plugin_dir_url = plugin_dir_url(__FILE__);
		self::$plugin_basename = basename(__FILE__);

		register_activation_hook(__FILE__, 'tinyShield::on_activation');

		//admin hooks and functions
		add_action('admin_menu', 'tinyShield_Admin::add_menu');
		add_action('admin_notices', 'tinyShield_Admin::notices', 99);
		add_action('admin_init', 'tinyShield::update_options');
		add_action('admin_enqueue_scripts', 'tinyShield_Admin::register_admin_resources');
		add_action('wp_dashboard_setup', 'tinyShield_Dashboard::dashboard_widget');
		add_action('current_screen', 'tinyShield_Admin::acknowledge_admin_notice');
		add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'tinyShield_Admin::add_additional_links');

		//hook to process incoming connections
		add_action('plugins_loaded', 'tinyShield::on_plugins_loaded', 0);

		//look for and possibly block user enumeration
		add_action('parse_request', 'tinyShield::log_user_enumeration', 20);

		//log 404s - could be a scanner if multiple 404s in rapid succession
		add_action('wp', 'tinyShield::log_404');

		//hook to process outgoing connections through the WordPress API
		add_filter('pre_http_request', 'tinyShield::outgoing_maybe_block', 10, 3);

		//hook into the failed login attempts and report back
		add_action('wp_login_failed', 'tinyShield::log_failed_login');

		//hooks into the user registration process and checks our blocklist
		add_filter('registration_errors', 'tinyShield::log_user_registration', 10, 3);

		//adds hook for spam comments - when someone marks a comment as spam it submits it tinyShield
		add_action('spam_comment', 'tinyShield::submit_spam_comment');

		//adds honeypot to registration form
		add_action('register_post', 'tinyShield::registration_form_check');
		add_action('login_form_register', 'tinyShield::registration_form_check');
		add_action('register_form', 'tinyShield::display_registration_honeypot', 99);
		add_action('login_head', 'tinyShield::registration_style', 99);
	}

	public static function update_options(){
		if(current_user_can('manage_options')){
			$options = get_option('tinyshield_options');

			$default_options = array(
				'subscription' => 'community',
				'license_id' => '0',
				'countries_to_block' => '',
				'countries_to_allow' => '',
				'report_failed_logins' => true,
				'brute_force_protection' => true,
				'report_spam_comments' => true,
				'report_user_registration' => true,
				'report_user_enumeration' => true,
				'registration_form_honeypot' => true,
				'registration_form_honeypot_key' => substr(str_shuffle('abcdefghijklmnopqrstuvwxyz'), 0, 10),
				'report_404' => false,
				'report_uri' => false,
				'pretty_deny' => true,
				'tinyshield_disabled' => false,
				'block_tor_exit_nodes' => false,
				'review_date' => strtotime('+30 days'),
				'license_error' => false,
				'cloudflare_enabled' => false,
				'cloudflare_email' => '',
				'cloudflare_auth_key' => '',
				'cloudflare_zone_id' => '',
				'cloudflare_ips' => '',
				'tinyshield_stats' => '',
				'db_version' => '056'
			);

			//upgrade routines
			if(!isset($options['db_version'])){
				tinyShieldUpgradeFunctions::upgrade_03_to_04();
				$options['db_version'] = '040';
			}

			if(isset($options['db_version']) && $options['db_version'] == '040'){
				tinyShieldUpgradeFunctions::upgrade_040_to_055();
				$options['db_version'] = '055';
			}

			if($options['db_version'] === false){
				$options['db_version'] = $default_options['db_version'];
			}

			if($options['registration_form_honeypot_key'] === false){
				$options['registration_form_honeypot_key'] = $default_options['registration_form_honeypot_key'];
			}

			if(empty($options)){ //incase we need to set the default options
				update_option('tinyshield_options', $default_options);
			}else{ //incase we need to update options
				$merged_options = array_replace($default_options, $options);
				update_option('tinyshield_options', $merged_options);
			}
		}
	}

	public static function on_activation(){
		if(!current_user_can('activate_plugins')){
			wp_die('You are not authorized to perform this operation.');
		}

		if(is_multisite()){
			deactivate_plugins(plugin_basename(__FILE__));
			wp_die('tinyShield is not compatible with WordPress multisite... yet.');
		}

		self::update_options();

		$cached_blocklist = get_option('tinyshield_cached_blocklist');
		$cached_allowlist = get_option('tinyshield_cached_allowlist');
		$cached_perm_allowlist = get_option('tinyshield_cached_perm_allowlist');
		$cached_perm_blocklist = get_option('tinyshield_cached_perm_blocklist');

		//set up our default block and allow lists
		if(!is_array($cached_blocklist)){
			$cached_blocklist = array();
			update_option('tinyshield_cached_blocklist', $cached_blocklist);
		}

		if(!is_array($cached_perm_blocklist)){
			$cached_perm_blocklist = array();
			update_option('tinyshield_cached_perm_blocklist', $cached_perm_blocklist);
		}

		if(!is_array($cached_perm_allowlist)){
			$cached_perm_allowlist = array();
			$ip = self::get_valid_ip();

			$perm_allowlist_entry = new stdClass();
			$perm_allowlist_entry->expires = strtotime('+30 years', time());
			$perm_allowlist_entry->ip_address = $ip;

			$cached_perm_allowlist[sha1($ip)] = json_encode($perm_allowlist_entry);
			update_option('tinyshield_cached_perm_allowlist', $cached_perm_allowlist);
		}

		if(!is_array($cached_allowlist)){
			$cached_allowlist = array();
			update_option('tinyshield_cached_allowlist', $cached_allowlist);
		}

	}

	public static function outgoing_maybe_block($pre, $args, $url){
		$options = get_option('tinyshield_options');

		if(empty($url) || !$host = parse_url($url, PHP_URL_HOST) || $options['tinyshield_disabled']){
			return $pre;
		}

		//bypass known good hosts
		$allowlisted_domains = array(
			'endpoint.tinyshield.me',
			'api.wordpress.org',
			'downloads.wordpress.org',
			parse_url(get_bloginfo('url'), PHP_URL_HOST)
		);

		if(in_array($host, $allowlisted_domains)){
			return $pre;
		}

		$ip = gethostbyname($host);
		$cached_blocklist = get_option('tinyshield_cached_blocklist');

		if(!empty($cached_blocklist) && array_key_exists(sha1($ip), $cached_blocklist)){
			$blocklist_data = json_decode($cached_blocklist[sha1($ip)]);
			if(is_object($blocklist_data)){
				$blocklist_data->last_attempt = time();

				$cached_blocklist[sha1($ip)] = json_encode($blocklist_data);
				update_option('tinyshield_cached_blocklist', $cached_blocklist);

				return true;
			}
		}

		if($result = self::check_ip($ip, 'outbound', $host)){
			self::write_log('tinyShield: outbound remote blocklist lookup: ' . $ip);

			return true;
		}

		return $pre;
	}

	public static function on_plugins_loaded() {
		$options = get_option('tinyshield_options');

		$orig_notice_file = plugin_dir_path(__FILE__) . 'tinyshield_block_notice.php';
		$dest_notice_file = ABSPATH . 'tinyshield_block_notice.php';

		if(!file_exists($dest_notice_file)){
			if(!copy($orig_notice_file, $dest_notice_file)){
				self::write_log('tinyShield: failed to copy block notice to root');
			}
		}

		if(!$options['tinyshield_disabled'] && self::incoming_maybe_block()){
			if($options['pretty_deny'] && file_exists(ABSPATH . 'tinyshield_block_notice.php')){
				wp_redirect(site_url('tinyshield_block_notice.php'));
				exit();
			}else{
				status_header(403);
				nocache_headers();
				exit();
			}
		}
	}

	public static function incoming_maybe_block(){
		$ip = self::get_valid_ip();

		self::clean_up_lists();

		self::write_log('------------------------------------------------------');
		self::write_log('tinyShield WAF: IP - ' . $ip);
		self::write_log('tinyShield WAF: Reqest Method - ' . $_SERVER['REQUEST_METHOD']);
		self::write_log('tinyShield WAF: Reqest - ' .json_encode($_REQUEST));
		self::write_log('------------------------------------------------------');

		//check if valid ip and check the local allowlist
		if(tinyShieldFunctions::is_activated() && $ip && !is_user_logged_in()){
			self::write_log('tinyShield: incoming remote blocklist lookup: ' . $ip);

			//check local perm allowlist
			self::write_log('tinyShield: checking perm allowlist');
			$cached_perm_allowlist = get_option('tinyshield_cached_perm_allowlist');
			if(!empty($cached_perm_allowlist) && array_key_exists(sha1($ip), $cached_perm_allowlist)){
				self::write_log('tinyShield: incoming ip found in local perm allowlist and was allowed: ' . $ip);
				return false;
			}

			//check local perm blocklist
			self::write_log('tinyShield: checking perm blocklist');
			$cached_perm_blocklist = get_option('tinyshield_cached_perm_blocklist');
			if(!empty($cached_perm_blocklist) && array_key_exists(sha1($ip), $cached_perm_blocklist)){
				self::write_log('tinyShield: incoming ip found in local perm blocklist and was blocked: ' . $ip);
				return true;
			}

			//check local cached allowlist
			self::write_log('tinyShield: checking cached allowlist');
			$cached_allowlist = get_option('tinyshield_cached_allowlist');
			if(!empty($cached_allowlist) && array_key_exists(sha1($ip), $cached_allowlist)){

				$data = json_decode($cached_allowlist[sha1($ip)]);
				if(is_object($data)){
					$data->last_attempt = time();

					$cached_allowlist[sha1($ip)] = json_encode($data);
					update_option('tinyshield_cached_allowlist', $cached_allowlist);

					self::write_log('tinyShield: incoming ip found in local allowlist and was allowed: ' . $ip);
					return false;
				}
			}

			//bot check
			self::write_log('tinyShield: checking if bot');
			if($bot = tinyShieldFunctions::is_bot($ip)){

				if(is_array($cached_allowlist)){
					$allow_bot = new stdClass();
					$allow_bot->expires = strtotime('+1 hour', time());
					$allow_bot->direction = 'inbound';
					$allow_bot->action = 'allow';
					$allow_bot->ip_address = $ip;
					$allow_bot->rdns = $bot->rdns;

					$allow_bot->geo_ip = array(
						'isp' => $bot->agent,
						'country_name' => __('Bot Detected', 'tinyshield'),
						'country_flag_emoji' => '🤖'
					);

					$allow_bot->last_attempt = time();

					$cached_allowlist[sha1($ip)] = json_encode($allow_bot);
					update_option('tinyshield_cached_allowlist', $cached_allowlist);

					do_action('tinyshield_allow_ip', $allow_bot);

					self::write_log('tinyShield: incoming ip has been detected as a bot and was allowed: ' . $ip);
					return false;
				}
			}

			//check local cached blocklist
			self::write_log('tinyShield: checking cached blocklist');
			$cached_blocklist = get_option('tinyshield_cached_blocklist');
			if(!empty($cached_blocklist) && array_key_exists(sha1($ip), $cached_blocklist)){

				$blocklist_data = json_decode($cached_blocklist[sha1($ip)]);
				if(is_object($blocklist_data)){
					$blocklist_data->last_attempt = time();
					$cached_blocklist[sha1($ip)] = json_encode($blocklist_data);
					update_option('tinyshield_cached_blocklist', $cached_blocklist);

					self::write_log('tinyShield: ip blocked from local cached blocklist: ' . $ip);
					return true;
				}
			}

			//ip does not exist locally at all, remote lookup needed
			self::write_log('tinyShield: check check_ip');
			if(self::check_ip($ip)){
				return true;
			}
		}

		return false; //default allow (failopen)
	}

	private static function check_ip($ip, $direction = 'inbound', $domain = ''){
		$options = get_option('tinyshield_options');
		$cached_blocklist = get_option('tinyshield_cached_blocklist');
		$cached_allowlist = get_option('tinyshield_cached_allowlist');

		$response = wp_remote_post(
			self::$tinyshield_check_url . '/' . $ip,
			array(
				'body' => array(
					'activation_key' => urlencode($options['site_activation_key']),
					'requesting_site' => urlencode(site_url())
				)
			)
		);

		$response_code = wp_remote_retrieve_response_code($response);
		$response_body = wp_remote_retrieve_body($response);

		if(!is_wp_error($response) && $response_code == 200){
			self::write_log('tinyShield: remote blocklist lookup response');
			self::write_log('tinyShield: ' . $response_body);

			$list_data = json_decode($response_body);

			if(!empty($response_body) && is_object($list_data)){
				$list_data->last_attempt = time();

				//update the subscription level from the servers response
				if($list_data->subscription != $options['subscription']){
					$options['subscription'] = filter_var($list_data->subscription, FILTER_SANITIZE_STRING);
					update_option('tinyshield_options', $options);
				}

				//set the license id for upgrades if applicable
				if($list_data->license_id != $options['license_id']){
					$options['license_id'] = absint($list_data->license_id);
					update_option('tinyshield_options', $options);
				}

				$selected_countries_to_block = unserialize($options['countries_to_block']);
				$selected_countries_to_allow = unserialize($options['countries_to_allow']);

				if($list_data->action == 'block' ||
				 (is_array($selected_countries_to_block) && in_array($list_data->geo_ip->country_code, $selected_countries_to_block)) ||
				 (is_array($selected_countries_to_allow) && !in_array($list_data->geo_ip->country_code, $selected_countries_to_allow)) ||
				 ($options['block_tor_exit_nodes'] && $list_data->is_tor_exit_node == 'yes')){

					$list_data->expires = strtotime('+24 hours', time());
					$list_data->direction = $direction;
					$list_data->action = 'block'; //sets action to block for logging purposes if country block or tor

					if($domain){
						$list_data->called_domain = $domain;
					}

					$cached_blocklist[sha1($ip)] = json_encode($list_data);
					update_option('tinyshield_cached_blocklist', $cached_blocklist);

					do_action('tinyshield_block_ip', $list_data);

					return true;

				}elseif($list_data->action == 'allow'){

					$list_data->expires = strtotime('+1 hour', time());
					$list_data->direction = $direction;
					if($domain){
						$list_data->called_domain = $domain;
					}
					$cached_allowlist[sha1($ip)] = json_encode($list_data);

					update_option('tinyshield_cached_allowlist', $cached_allowlist);

					do_action('tinyshield_allow_ip', $list_data);

					return false;
				}
			}
		}else{
			self::write_log('tinyShield: check_ip error');
			if(is_wp_error($response)){
				self::write_log($response_code . ': ' . $response->get_error_message());
			}

			if($response_code == 403){
				$options['license_error'] = true;
			}
		}

		return false; //default to allow in case of emergency
	}

	private static function clean_up_lists(){
		$cached_blocklist = get_option('tinyshield_cached_blocklist');
		$cached_allowlist = get_option('tinyshield_cached_allowlist');

		if(is_array($cached_blocklist) && !empty($cached_blocklist)){

			foreach($cached_blocklist as $iphash => $iphash_data){
				$iphash_data = json_decode($iphash_data);
				if(is_object($iphash_data) && $iphash_data->expires < time()){

					do_action('tinyshield_blocklist_clear_ip', $iphash);

					unset($cached_blocklist[$iphash]);
				}
			}

			update_option('tinyshield_cached_blocklist', $cached_blocklist);
		}

		if(is_array($cached_allowlist) && !empty($cached_allowlist)){
			foreach($cached_allowlist as $iphash => $iphash_data){
				$iphash_data = json_decode($iphash_data);
				if(is_object($iphash_data) && $iphash_data->expires < time()){

					do_action('tinyshield_allowlist_clear_ip', $iphash);

					unset($cached_allowlist[$iphash]);
				}
			}
			update_option('tinyshield_cached_allowlist', $cached_allowlist);
		}
	}

	private static function get_valid_ip(){
	  //supports ipv4 and ipv6

	  //if cloudflare, set the remote_addr to the original
	  if(isset($_SERVER['HTTP_CF_CONNECTING_IP'])){
	    $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_CF_CONNECTING_IP'];
	  }

		if(isset($_SERVER['HTTP_X_FORWARDED_FOR'])){
			$_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_X_FORWARDED_FOR'];
		}

	  if(filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)){
	    return $_SERVER['REMOTE_ADDR'];
	  }

	  return false;
	}

	public static function write_log($log){
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
					'optin' => $registration_data['optin'],
					'action' => 'activate'
				)
			)
		);

		if(is_wp_error($return) || wp_remote_retrieve_response_code($return) != 200){
			return false;
		}

		$response = json_decode(wp_remote_retrieve_body($return));
		if(is_object($response)){
			if(!empty($response->message) && $response->message == 'activated'){
				return $response;
			}elseif(!empty($response->message)){
				return filter_var($response->message, FILTER_SANITIZE_STRING);
			}else{
				return false;
			}
		}

		return false;
	}

	public static function log_404(){
		if(is_404()){
			$options = get_option('tinyshield_options');

			if(!tinyShieldFunctions::is_activated() && !$options['report_404']){
				return;
			}

			if(is_user_logged_in()){
				return;
			}

			$response = wp_remote_post(
				self::$tinyshield_report_url,
				array(
					'body' => array(
						'ip_to_report' => self::get_valid_ip(),
						'type' => '404',
						'reporting_site' => site_url(),
						'time_of_occurance' => time()
					)
				)
			);
		}
	}

	public static function log_user_enumeration(){
		$options = get_option('tinyshield_options');

		if(!tinyShieldFunctions::is_activated() && !$options['report_user_enumeration']){
			return;
		}

		if(is_user_logged_in()){
			return;
		}


		if(!isset($_REQUEST['author']) && !isset($_REQUEST['author_name'])){
			return;
		}

		if(!get_option('permalink_structure')){
			return;
		}

		$response = wp_remote_post(
			self::$tinyshield_report_url,
			array(
				'body' => array(
					'ip_to_report' => self::get_valid_ip(),
					'type' => 'user_enumeration',
					'reporting_site' => site_url(),
					'time_of_occurance' => time()
				)
			)
		);
	}

	public static function submit_spam_comment($comment_id){
		$options = get_option('tinyshield_options');

		if(tinyShieldFunctions::is_activated() && $options['report_spam_comments']){
			$comment = get_comment($comment_id);

			$response = wp_remote_post(
				self::$tinyshield_report_url,
				array('body' => array(
					'ip_to_report' => $comment->comment_author_IP,
					'type' => 'spam_comment',
					'reporting_site' => site_url(),
					'time_of_occurance' => time()
				))
			);
		}
	}

	public static function log_failed_login($username){
		$options = get_option('tinyshield_options');
		$remote_ip = self::get_valid_ip();

		if(tinyShieldFunctions::is_activated() && $options['brute_force_protection'] && $tries = get_transient('tinyShield_' . sha1($remote_ip))){
			$tries++;
			if($tries >= 10){
				$cached_blocklist = get_option('tinyshield_cached_blocklist');
				$cached_allowlist = get_option('tinyshield_cached_allowlist');

				$brute_force = new stdClass();
				$brute_force->expires = strtotime('+24 hours', time());
				$brute_force->direction = 'inbound';
				$brute_force->action = 'block';
				$brute_force->ip_address = $remote_ip;
				$brute_force->rdns = gethostbyaddr($remote_ip);

				$brute_force->geo_ip = array(
					'isp' => '',
					'country_name' => __('Brute Force Attacker', 'tinyshield'),
					'country_flag_emoji' => '🔒'
				);

				$brute_force->last_attempt = time();

				do_action('tinyshield_block_ip', $brute_force);

				$cached_blocklist[sha1($remote_ip)] = json_encode($brute_force);
				update_option('tinyshield_cached_blocklist', $cached_blocklist);

				unset($cached_allowlist[sha1($remote_ip)]);
				update_option('tinyshield_cached_allowlist', $cached_allowlist);
				delete_transient('tinyShield_' . sha1($remote_ip));

				self::write_log('tinyShield: incoming ip has been detected as brute forcing the site and was blocked: ' . $ip);
			}else{
				delete_transient('tinyShield_' . sha1($remote_ip));
				set_transient('tinyShield_' . sha1($remote_ip), $tries, 86400);
			}
		}else{
			set_transient('tinyShield_' . sha1($remote_ip), 1, 86400);
		}

		if($options['report_failed_logins']){
			if($remote_ip){
				$response = wp_remote_post(
					self::$tinyshield_report_url,
					array(
						'body' => array(
							'ip_to_report' => $remote_ip,
							'type' => 'failed_logins',
							'username_tried' => $username,
							'reporting_site' => site_url(),
							'time_of_occurance' => time()
						)
					)
				);
			}
		}
	}

	public static function log_user_registration($errors, $user, $email){
		$options = get_option('tinyshield_options');

		if(tinyShieldFunctions::is_activated() && $options['report_user_registration']){
			$remote_ip = self::get_valid_ip();

			if($remote_ip){
				$response = wp_remote_post(
					self::$tinyshield_report_url,
					array(
						'body' => array(
							'ip_to_report' => $remote_ip,
							'type' => 'user_registration',
							'username_tried' => $username,
							'reporting_site' => site_url(),
							'time_of_occurance' => time()
						)
					)
				);
			}
		}

		return $errors;
	}

	public static function registration_form_check(){
		$options = get_option('tinyshield_options');

		if(tinyShieldFunctions::is_activated() && $options['registration_form_honeypot']){
			if(isset($_POST[$options['registration_form_honeypot_key'] . '_name']) && !empty($_POST[$options['registration_form_honeypot_key'] . '_name'])){
				if(!$options['tinyshield_disabled'] && $options['report_user_registration']){
					$remote_ip = self::get_valid_ip();

					if($remote_ip){
						$response = wp_remote_post(
							self::$tinyshield_report_url,
							array(
								'body' => array(
									'ip_to_report' => $remote_ip,
									'type' => 'user_registration',
									'username_tried' => $username,
									'reporting_site' => site_url(),
									'time_of_occurance' => time()
								)
							)
						);
					}

					if($options['pretty_deny'] && file_exists(ABSPATH . 'tinyshield_block_notice.php')){
						wp_redirect(site_url('tinyshield_block_notice.php'));
						exit();
					}else{
						status_header(403);
						nocache_headers();
						exit();
					}
				}
			}
		}
	}

	public static function registration_style(){
		$options = get_option('tinyshield_options');
?>
		<style type="text/css">p.<?php esc_attr_e($options['registration_form_honeypot_key']); ?>_name_field { display: none; !important}</style>
<?php
	}

	public static function registration_scripts(){
		$options = get_option('tinyshield_options');
?>
		<script type="text/javascript">jQuery('#<?php esc_attr_e($options['registration_form_honeypot_key']); ?>_name').val('');</script>
<?php
	}

	public static function display_registration_honeypot(){
		$options = get_option('tinyshield_options');

		wp_enqueue_script( 'jquery' );
		add_action('login_footer', 'tinyShield::registration_scripts', 25);
?>
		<p class="<?php esc_attr_e($options['registration_form_honeypot_key']); ?>_name_field">
			<label for="<?php esc_attr_e($options['registration_form_honeypot_key']); ?>_name_field">
					<?php _e('Do not fill this out.'); ?>
			</label>
			<input type="text" name="<?php esc_attr_e($options['registration_form_honeypot_key']); ?>_name" id="<?php esc_attr_e($options['registration_form_honeypot_key']); ?>_name" class="input" value="" size="25" autocomplete="off" />
		</p>
<?php
	}

	public static function analyze_request_uri(){
		$url = $_SERVER['REQUEST_URI'];
		$ip = self::get_valid_ip();
		$options = get_option('tinyshield_options');

		if(!$options['report_uri']){
			return;
		}

		if(is_user_logged_in()){
			return;
		}

		$response = wp_remote_post(
			self::$tinyshield_report_url,
			array(
				'body' => array(
					'ip_to_report' => self::get_valid_ip(),
					'type' => 'report_uri',
					'reporting_site' => site_url(),
					'time_of_occurance' => time(),
					'uri' => urlencode($url)
				)
			)
		);
	}

} //End tinyShield Class

$tinyShield = new tinyShield();
