<?php
/*
Plugin Name: tinyShield - Simple. Focused. Security.
Version: 0.6.0
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

include_once(plugin_dir_path(__FILE__) . 'lib/tables/blocklist_tables.php');
include_once(plugin_dir_path(__FILE__) . 'lib/tables/allowlist_tables.php');
include_once(plugin_dir_path(__FILE__) . 'lib/tables/activity_log_tables.php');
include_once(plugin_dir_path(__FILE__) . 'lib/tables/perm_allowlist_tables.php');
include_once(plugin_dir_path(__FILE__) . 'lib/tables/perm_blocklist_tables.php');
include_once(plugin_dir_path(__FILE__) . 'lib/upgrade/functions.php');
include_once(plugin_dir_path(__FILE__) . 'lib/functions.php');

class tinyShield{

	private static $tinyshield_report_url = 'https://endpoint.tinyshield.me/report';
	private static $tinyshield_check_url = 'https://endpoint.tinyshield.me/checkv3';
	private static $tinyshield_upgrade_url = 'https://tinyshield.me/upgrade-my-site/';
	private static $tinyshield_activation_url = 'https://endpoint.tinyshield.me/activatev2';

	public function __construct(){
		register_activation_hook(__FILE__, 'tinyShield::on_activation');

		add_action('admin_menu', 'tinyShield::add_menu');
		add_action('admin_notices', 'tinyShield::notices', 99);
		add_action('admin_init', 'tinyShield::update_options');
		add_action('admin_enqueue_scripts', 'tinyShield::register_admin_resources');

		add_action('current_screen', 'tinyShield::acknowledge_admin_notice');

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

	public static function notices(){
		$options = get_option('tinyshield_options');
?>
		<?php if(current_user_can('manage_options') && empty($options['site_activation_key'])): ?>
			<div class="notice notice-error"><p><strong><?php _e('tinyShield: tinyShield is not currently activated. Before we can help protect your site, you must register your site. You can do that here <a href="' . admin_url('admin.php?page=tinyshield.php&tab=settings') . '">tinyShield Settings</a> under Site Activation.', 'tinyshield');?></strong></p></div>
		<?php endif; ?>

		<?php if(current_user_can('manage_options') && $options['tinyshield_disabled']): ?>
			<div class="notice notice-warning"><p><strong><?php _e('tinyShield: tinyShield is currently disabled and not protecting your site. To re-enable tinyShield, you can do that under the options here <a href="' . admin_url('admin.php?page=tinyshield.php&tab=settings') . '">tinyShield Settings</a> under Options.', 'tinyshield');?></strong></p></div>
		<?php endif; ?>

		<?php if(current_user_can('manage_options') && !is_null($options['subscription']) && $options['subscription'] == 'community' && $options['review_date'] >= current_time('timestamp') && empty(get_user_meta(get_current_user_id(), 'tinyshield_review_notice'))): ?>
			<style>
					p.review {
							position: relative;
							margin-left: 35px;
							padding: 1px;
					}
					p.review span.dashicons-heart {
							color: white;
							background: #66BB6A;
							position: absolute;
							left: -50px;
							padding: 9px;
							top: -8px;
					}

					p.review strong {
							color: #66BB6A;
					}

					p.review a.dismiss {
							float: right;
							text-decoration: none;
							color: #66BB6A;
					}
			</style>

			<?php
				$active_tab = isset($_GET['tab']) ? $_GET['tab'] : 'log';
				$nag_admin_dismiss_url = "admin.php?page=tinyshield.php&tab=" . $active_tab . "&dismiss_tinyshield_nag=1";
				$plugin_review_url = "https://wordpress.org/support/plugin/tinyshield/reviews/#new-post";
			?>
			<div class="notice notice-success"><p class="review"><span class="dashicons dashicons-heart"></span><strong><?php _e('tinyShield: Are you seeing benefit out of tinyShield? Consider <a target="_blank" href="'. esc_attr(add_query_arg('site_activation_key', $options['site_activation_key'], self::$tinyshield_upgrade_url)) .'">upgrading to our professional plan</a> for lots of additional features or consider leaving us a <a target="_blank" href="' . esc_attr($plugin_review_url) . '">plugin review</a>!'); ?> <a href="<?php echo esc_url(admin_url($nag_admin_dismiss_url)); ?>" class="dismiss"><span class="dashicons dashicons-dismiss"></span></a></strong></p></div>
		<?php endif; ?>
<?php
	}

	public static function acknowledge_admin_notice(){
		if(isset($_GET['dismiss_tinyshield_nag']) && $_GET['dismiss_tinyshield_nag'] == '1'){
			add_user_meta(get_current_user_id(), 'tinyshield_review_notice', 'true', true);
		}
	}

	public static function register_admin_resources($page){
		if($page == 'toplevel_page_tinyshield'){
			wp_enqueue_script('select2', plugin_dir_url(__FILE__) . 'lib/js/select2.min.js', array('jquery'), '4.0.13', true);
			wp_enqueue_script('tinyshield-select2-custom', plugin_dir_url(__FILE__) . 'lib/js/tinyshield.custom.js', array('jquery', 'select2'), '1.0.0', true);
			wp_enqueue_style('tinyshield-select2-css', plugin_dir_url(__FILE__) . 'lib/css/select2.min.css');
			wp_enqueue_style('tinyshield-css', plugin_dir_url(__FILE__) . 'lib/css/tinyshield.css');
		}
	}

	public static function add_menu(){
		if(function_exists('add_menu_page')){
			add_menu_page('tinyShield', 'tinyShield', 'manage_options', basename(__FILE__), 'tinyShield::display_options', plugin_dir_url(__FILE__) . 'img/tinyshield.png');
			add_submenu_page(basename(__FILE__), 'tinyShield', 'Activity Log', 'manage_options', basename(__FILE__), 'tinyShield::display_options');
			add_submenu_page(basename(__FILE__), 'Permanent Allowlist', 'Permanent Allowlist', 'manage_options', 'tinyshield.php&tab=perm-allowlist', 'tinyShield::display_options');
			add_submenu_page(basename(__FILE__), 'Permanent Blocklist', 'Permanent Blocklist', 'manage_options', 'tinyshield.php&tab=perm-blocklist', 'tinyShield::display_options');
			add_submenu_page(basename(__FILE__), 'Allowlist', 'Allowlist', 'manage_options', 'tinyshield.php&tab=allowlist', 'tinyShield::display_options');
			add_submenu_page(basename(__FILE__), 'Blocklist', 'Blocklist', 'manage_options', 'tinyshield.php&tab=blocklist', 'tinyShield::display_options');
			add_submenu_page(basename(__FILE__), 'Settings', 'Settings', 'manage_options', 'tinyshield.php&tab=settings', 'tinyShield::display_options');
		}
	}

	public static function update_options(){
		if(current_user_can('manage_options')){
			$options = get_option('tinyshield_options');

			$default_options = array(
				'subscription' => 'community',
				'countries_to_block' => '',
				'countries_to_allow' => '',
				'report_failed_logins' => true,
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
				'db_version' => '055'
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

			$perm_allowlist_entry = new stdClass();
			$perm_allowlist_entry->expires = strtotime('+30 years', current_time('timestamp'));

			$cached_perm_allowlist[sha1(self::get_valid_ip())] = json_encode($perm_allowlist_entry);
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
				$blocklist_data->last_attempt = current_time('timestamp');

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

		//check if valid ip and check the local allowlist
		if(tinyShieldFunctions::is_activated() && $ip && !is_user_logged_in()){

			//check local perm allowlist
			$cached_perm_allowlist = get_option('tinyshield_cached_perm_allowlist');
			if(!empty($cached_perm_allowlist) && array_key_exists(sha1($ip), $cached_perm_allowlist)){
				self::write_log('tinyShield: incoming ip found in local perm allowlist and was allowed: ' . $ip);
				return false;
			}

			//check local perm blocklist
			$cached_perm_blocklist = get_option('tinyshield_cached_perm_blocklist');
			if(!empty($cached_perm_blocklist) && array_key_exists(sha1($ip), $cached_perm_blocklist)){
				self::write_log('tinyShield: incoming ip found in local perm blocklist and was blocked: ' . $ip);
				return true;
			}

			//check local cached allowlist
			$cached_allowlist = get_option('tinyshield_cached_allowlist');
			if(!empty($cached_allowlist) && array_key_exists(sha1($ip), $cached_allowlist)){

				$data = json_decode($cached_allowlist[sha1($ip)]);
				if(is_object($data)){
					$data->last_attempt = current_time('timestamp');

					$cached_allowlist[sha1($ip)] = json_encode($data);
					update_option('tinyshield_cached_allowlist', $cached_allowlist);

					self::write_log('tinyShield: incoming ip found in local allowlist and was allowed: ' . $ip);
					return false;
				}
			}

			//check local cached blocklist
			$cached_blocklist = get_option('tinyshield_cached_blocklist');
			if(!empty($cached_blocklist) && array_key_exists(sha1($ip), $cached_blocklist)){

				$blocklist_data = json_decode($cached_blocklist[sha1($ip)]);
				if(is_object($blocklist_data)){
					$blocklist_data->last_attempt = current_time('timestamp');
					$cached_blocklist[sha1($ip)] = json_encode($blocklist_data);
					update_option('tinyshield_cached_blocklist', $cached_blocklist);

					self::write_log('tinyShield: ip blocked from local cached blocklist: ' . $ip);
					return true;
				}
			}

			//ip does not exist locally at all, remote lookup needed
			self::write_log('tinyShield: incoming remote blocklist lookup: ' . $ip);
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

		if(!is_wp_error($response)){
			self::write_log('tinyShield: remote blocklist lookup response');
			self::write_log('tinyShield: ' . $response_body);

			if(!empty($response_body)){

				$list_data = json_decode($response_body);
				if(is_object($list_data)){
					$list_data->last_attempt = current_time('timestamp');

					//update the subscription level from the servers response
					if($list_data->subscription != $options['subscription']){
						$options['subscription'] = sanitize_text_field($list_data->subscription);
						update_option('tinyshield_options', $options);
					}

					$selected_countries_to_block = unserialize($options['countries_to_block']);
					$selected_countries_to_allow = unserialize($options['countries_to_allow']);

					if($list_data->action == 'block' ||
					 (is_array($selected_countries_to_block) && in_array($list_data->geo_ip->country_code, $selected_countries_to_block)) ||
					 (is_array($selected_countries_to_allow) && !in_array($list_data->geo_ip->country_code, $selected_countries_to_allow)) ||
					 ($options['block_tor_exit_nodes'] && $list_data->is_tor_exit_node == 'yes')){

						$list_data->expires = strtotime('+24 hours', current_time('timestamp'));
						$list_data->direction = $direction;
						$list_data->action = 'block'; //sets action to block for logging purposes if country block or tor

						if($domain){
							$list_data->called_domain = $domain;
						}

						$cached_blocklist[sha1($ip)] = json_encode($list_data);
						update_option('tinyshield_cached_blocklist', $cached_blocklist);

						return true;

					}elseif($list_data->action == 'allow'){

						$list_data->expires = strtotime('+1 hour', current_time('timestamp'));
						$list_data->direction = $direction;
						if($domain){
							$list_data->called_domain = $domain;
						}
						$cached_allowlist[sha1($ip)] = json_encode($list_data);

						update_option('tinyshield_cached_allowlist', $cached_allowlist);
						return false;
					}
				}

				return false; //default to allow in case of emergency
			}
		}else{
			self::write_log('tinyShield: check_ip error');
			self::write_log($response->get_error_message());
		}
	}

	private static function clean_up_lists(){
		$cached_blocklist = get_option('tinyshield_cached_blocklist');
		$cached_allowlist = get_option('tinyshield_cached_allowlist');

		if(is_array($cached_blocklist) && !empty($cached_blocklist)){
			foreach($cached_blocklist as $iphash => $iphash_data){
				$iphash_data = json_decode($iphash_data);
				if(is_object($iphash_data) && $iphash_data->expires < current_time('timestamp')){
					unset($cached_blocklist[$iphash]);
				}
			}

			update_option('tinyshield_cached_blocklist', $cached_blocklist);
		}

		if(is_array($cached_allowlist) && !empty($cached_allowlist)){
			foreach($cached_allowlist as $iphash => $iphash_data){
				$iphash_data = json_decode($iphash_data);
				if(is_object($iphash_data) && $iphash_data->expires < current_time('timestamp')){
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
				return sanitize_text_field($response->message);
			}else{
				return false;
			}
		}

		return false;
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

		if(in_array(wp_remote_retrieve_body($return), array('site_key_deactivated', 'site_key_mismatch'))){
			return true;
		}

		return false;
	}

	public static function log_404(){
		if(is_404()){
			$options = get_option('tinyshield_options');

			if(!$options['report_404']){
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
						'time_of_occurance' => current_time('timestamp')
					)
				)
			);
		}
	}

	public static function log_user_enumeration(){
		$options = get_option('tinyshield_options');

		if(!$options['report_user_enumeration']){
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
					'time_of_occurance' => current_time('timestamp')
				)
			)
		);
	}

	public static function submit_spam_comment($comment_id){
		$options = get_option('tinyshield_options');

		if($options['report_spam_comments']){
			$comment = get_comment($comment_id);

			$response = wp_remote_post(
				self::$tinyshield_report_url,
				array('body' => array(
					'ip_to_report' => $comment->comment_author_IP,
					'type' => 'spam_comment',
					'reporting_site' => site_url(),
					'time_of_occurance' => current_time('timestamp')
				))
			);
		}
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

	public static function log_user_registration($errors, $user, $email){
		$options = get_option('tinyshield_options');

		if($options['report_user_registration']){
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
							'time_of_occurance' => current_time('timestamp')
						)
					)
				);
			}
		}

		return $errors;
	}

	public static function registration_form_check(){
		$options = get_option('tinyshield_options');

		if($options['registration_form_honeypot']){
			if(isset($_POST[$options['registration_form_honeypot_key'] . '_name']) && !empty($_POST[$options['registration_form_honeypot_key'] . '_name'])){
				if(!$options['tinyshield_disabled']){

					//if user registration is enabled
					if($options['report_user_registration']){
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
										'time_of_occurance' => current_time('timestamp')
									)
								)
							);
						}
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
					'time_of_occurance' => current_time('timestamp'),
					'uri' => urlencode($url)
				)
			)
		);
	}

	public static function display_options(){
		if(!current_user_can('manage_options')){
			_e('You are not authorized to perform this operation.', 'tinyshield');
			die();
		}

		$options = get_option('tinyshield_options');
		$cached_blocklist = get_option('tinyshield_cached_blocklist');
		$cached_allowlist = get_option('tinyshield_cached_allowlist');
		$cached_perm_allowlist = get_option('tinyshield_cached_perm_allowlist');
		$cached_perm_blocklist = get_option('tinyshield_cached_perm_blocklist');

		$errors = '';
		$alerts = '';

		$success_messages = array(
			'site_key_activated' => __('Your site is now activated!', 'tinyshield'),
			'site_key_deactivated' => __('Site Key Deactivated', 'tinyshield'),
			'settings_updated' => __('Settings Updated', 'tinyshield'),
			'blocklist_cleared' => __('Local Blocklist Has Been Cleared', 'tinyshield'),
			'perm_blocklist_cleared' => __('Permanent Blocklist Has Been Cleared', 'tinyshield'),
			'allowlist_cleared' => __('Local Allowlist Has Been Cleared', 'tinyshield'),
			'reported_false_positive' => __('Your report has been logged. Thanks for reporting, we\'ll check it out!', 'tinyshield')
		);

		$error_messages = array(
			'key_not_found' => __('Sorry, this key was not found. Please try again.', 'tinyshield'),
			'key_in_use' => __('Sorry, this site has already been activated. Please contact support.', 'tinyshield'),
			'key_expired' => __('This key is expired. Please renew your key.', 'tinyshield'),
			'key_banned' => __('This key has been banned.', 'tinyshield'),
			'something_went_wrong' => __('Something went wrong but we\'re not sure what...', 'tinyshield'),
			'missing_registration_data' => __('You must provide your first name, last name, and email address to register your site.', 'tinyshield'),
			'ip_could_not_be_found' => __('The IP could not be found.', 'tinyshield')
		);

		/*****************************************
				Settings Page Update
		*****************************************/
		if(isset($_POST['tinyshield_save_options']) && $_POST['tinyshield_action'] == 'options_save' && wp_verify_nonce($_POST['_wpnonce'], 'tinyshield-update-options')) {
			if(is_array($_POST['options']) && !empty($_POST['options'])){
				foreach($options as $key => $value){
					if(array_key_exists($key, $_POST['options'])){
						if(is_null($value)){
							$options[$key] = false;
						}elseif(is_array($_POST['options'][$key]) || is_object($_POST['options'][$key])){
							$options[$key] = serialize($_POST['options'][$key]);
						}elseif(filter_var($_POST['options'][$key], FILTER_VALIDATE_BOOLEAN)){
							$options[$key] = true;
						}else{
							$options[$key] = sanitize_text_field($value);
						}
					}else{
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
					'optin' => sanitize_text_field($_POST['activate']['optin']),
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
			Handle clearing of local blocklist
		*****************************************/
		if(isset($_POST['tinyshield_action']) && $_POST['tinyshield_action'] == 'clear_cached_blocklist' && wp_verify_nonce($_POST['_wpnonce'], 'tinyshield-clear-local-blocklist')){
			$cached_blocklist = array();
			update_option('tinyshield_cached_blocklist', $cached_blocklist);

			$alerts = $success_messages['blocklist_cleared'];
		}

		/*****************************************
			Handle clearing of local allowlist
		*****************************************/
		if(isset($_POST['tinyshield_action']) && $_POST['tinyshield_action'] == 'clear_cached_allowlist' && wp_verify_nonce($_POST['_wpnonce'], 'tinyshield-clear-local-allowlist')){
			$cached_allowlist = array();
			update_option('tinyshield_cached_allowlist', $cached_allowlist);

			$alerts = $success_messages['allowlist_cleared'];
		}

		/*****************************************
			Handle clearing of permanent blocklist
		*****************************************/
		if(isset($_POST['tinyshield_action']) && $_POST['tinyshield_action'] == 'clear_permanent_blocklist' && wp_verify_nonce($_POST['_wpnonce'], 'tinyshield-clear-permanent-blocklist')){
			$cached_perm_blocklist = array();
			update_option('tinyshield_cached_perm_blocklist', $cached_perm_blocklist);

			$alerts = $success_messages['perm_blocklist_cleared'];
		}

		/*****************************************
			Handle Reporting of False Positives
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'report_false_positive' && tinyShieldFunctions::is_sha1($_GET['iphash']) && wp_verify_nonce($_GET['_wpnonce'], 'tinyshield-report-false-positive')){

			if(!empty($cached_allowlist[$_GET['iphash']])){
				$meta = json_decode($cached_allowlist[$_GET['iphash']]);
				if(is_object($meta)){
					$ip_to_report = $meta->ip_address;
				}
			}elseif(!empty($cached_blocklist[$_GET['iphash']])){
				$meta = json_decode($cached_blocklist[$_GET['iphash']]);
				if(is_object($meta)){
					$ip_to_report = $meta->ip_address;
				}
			}

			if(!empty($ip_to_report)){
				$response = wp_remote_post(
					self::$tinyshield_report_url,
					array(
						'body' => array(
							'ip_to_report' => $ip_to_report,
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
			}else{
				$errors = $error_messages['ip_could_not_be_found'];
			}

		}

		/*****************************************
			Add Custom IP to Permanent Allowlist Action
		******************************************/
		if(isset($_POST['tinyshield_perm_allowlist_update']) && wp_verify_nonce($_POST['_wpnonce'], 'update-tinyshield-perm-allowlist') && !empty($_POST['perm_ip_to_allowlist'])){
				$ips = array_filter(array_map('trim', explode("\r\n", $_POST['perm_ip_to_allowlist'])));

				foreach($ips as $ip){
					if(!empty($ip) && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)){
						$perm_allowlist_entry = new stdClass();
						$perm_allowlist_entry->expires = strtotime('+30 years', current_time('timestamp'));
						$perm_allowlist_entry->ip_address = $ip;
						$cached_perm_allowlist[sha1($ip)] = json_encode($perm_allowlist_entry);
					}else{
						$invalid_ip = true;
					}
				}

				if(isset($invalid_ip)){
?>
					<div class="error"><p><strong><?php _e('Invalid IP detected. Please ensure all IP addresses are valid.', 'tinyshield');?></strong></p></div>
<?php
				}else{
					update_option('tinyshield_cached_perm_allowlist', $cached_perm_allowlist);
?>
					<div class="updated"><p><strong><?php _e('IP Address has been added to the Permanent Allowlist', 'tinyshield');?></strong></p></div>
<?php
				}
		}

		/*****************************************
			Add Custom IP to Permanent Blocklist Action
		******************************************/
		if(isset($_POST['tinyshield_perm_blocklist_update']) && wp_verify_nonce($_POST['_wpnonce'], 'update-tinyshield-perm-blocklist') && !empty($_POST['perm_ip_to_blocklist'])){
				$ips = array_filter(array_map('trim', explode("\r\n", $_POST['perm_ip_to_blocklist'])));

				foreach($ips as $ip){
					if(!empty($ip) && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)){
						$perm_blocklist_entry = new stdClass();
						$perm_blocklist_entry->expires = strtotime('+30 years', current_time('timestamp'));
						$perm_blocklist_entry->ip_address = $ip;
						$cached_perm_blocklist[sha1($ip)] = json_encode($perm_blocklist_entry);

						if(array_key_exists(sha1($ip), $cached_allowlist)){
							unset($cached_allowlist[sha1($ip)]);
						}

					}else{
						$invalid_ip = true;
					}
				}

				if(isset($invalid_ip) && $invalid_ip){
?>
					<div class="error"><p><strong><?php _e('Invalid IP detected. Please ensure all IP addresses are valid.', 'tinyshield');?></strong></p></div>
<?php
				}else{
					update_option('tinyshield_cached_allowlist', $cached_allowlist);
					update_option('tinyshield_cached_perm_blocklist', $cached_perm_blocklist);
?>
					<div class="updated"><p><strong><?php _e('IP Address has been added to the Permanent Blocklist', 'tinyshield');?></strong></p></div>
<?php
				}
		}

		/*****************************************
		 	Delete Perm Blocklist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'delete-perm-blocklist' && tinyShieldFunctions::is_sha1($_GET['iphash']) && wp_verify_nonce($_GET['_wpnonce'], 'delete-tinyshield-perm-blocklist-item')){
			unset($cached_perm_blocklist[$_GET['iphash']]);
			update_option('tinyshield_cached_perm_blocklist', $cached_perm_blocklist);
?>
			<div class="updated"><p><strong><?php _e('IP Address has been removed from the Permanent Blocklist', 'tinyshield');?></strong></p></div>
<?php
		}

		/*****************************************
		 	Delete Perm Allowlist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'delete-perm-allowlist' && tinyShieldFunctions::is_sha1($_GET['iphash']) && wp_verify_nonce($_GET['_wpnonce'], 'delete-tinyshield-perm-allowlist-item')){
			unset($cached_perm_allowlist[$_GET['iphash']]);
			update_option('tinyshield_cached_perm_allowlist', $cached_perm_allowlist);
?>
			<div class="updated"><p><strong><?php _e('IP Address has been removed from the Permanent Allowlist', 'tinyshield');?></strong></p></div>
<?php
		}

		/*****************************************
		 	Move to Blocklist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'add_to_blocklist' && tinyShieldFunctions::is_sha1($_GET['iphash']) && wp_verify_nonce($_GET['_wpnonce'], 'tinyshield-move-item-blocklist')){
			$new_bl_item = json_decode($cached_allowlist[$_GET['iphash']]);
			if(is_object($new_bl_item)){
				$new_bl_item->action = 'block';
				$new_bl_item->date_added = current_time('timestamp');
				$new_bl_item->expires = strtotime('+24 hours', current_time('timestamp'));

				$cached_blocklist[$_GET['iphash']] = json_encode($new_bl_item);

				unset($cached_allowlist[$_GET['iphash']]);

				update_option('tinyshield_cached_allowlist', $cached_allowlist);
				update_option('tinyshield_cached_blocklist', $cached_blocklist);
?>
			<div class="updated"><p><strong><?php _e('The IP Address has been placed in the Blocklist for 24 hours.', 'tinyshield');?></strong></p></div>
<?php
			}
		}

		/*****************************************
		 	Move to Perm Allowlist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'add_to_perm_allowlist' && tinyShieldFunctions::is_sha1($_GET['iphash']) && wp_verify_nonce($_GET['_wpnonce'], 'tinyshield-move-item-perm-allowlist')){
			if(!empty($cached_allowlist[$_GET['iphash']])){
				$cached_perm_allowlist[$_GET['iphash']] = $cached_allowlist[$_GET['iphash']];
				unset($cached_allowlist[$_GET['iphash']]);
			}elseif(!empty($cached_blocklist[$_GET['iphash']])){
				$cached_perm_allowlist[$_GET['iphash']] = $cached_blocklist[$_GET['iphash']];
				unset($cached_blocklist[$_GET['iphash']]);
			}

			update_option('tinyshield_cached_perm_allowlist', $cached_perm_allowlist);
			update_option('tinyshield_cached_allowlist', $cached_allowlist);
			update_option('tinyshield_cached_blocklist', $cached_blocklist);
?>
			<div class="updated"><p><strong><?php _e('The IP Address has been placed in the Permanent Allowlist.', 'tinyshield');?></strong></p></div>
<?php
		}

		/*****************************************
			Delete IP Address from Blocklist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'remove_from_blocklist' && tinyShieldFunctions::is_sha1($_GET['iphash']) && wp_verify_nonce($_GET['_wpnonce'], 'tinyshield-delete-blocklist-item')){
			unset($cached_blocklist[$_GET['iphash']]);
			update_option('tinyshield_cached_blocklist', $cached_blocklist);
?>
			<div class="updated"><p><strong><?php _e('The IP Address has been removed from the Blocklist. If this IP is trys to connect to your site again, it will be rechecked.', 'tinyshield');?></strong></p></div>
<?php
		}

		/*****************************************
			Move to Allowlist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'add_to_allowlist' && tinyShieldFunctions::is_sha1($_GET['iphash']) && wp_verify_nonce($_GET['_wpnonce'], 'tinyshield-move-item-allowlist')){
			$new_wl_item = json_decode($cached_blocklist[$_GET['iphash']]);
			if(is_object($new_wl_item)){
				$new_wl_item->action = 'allow';
				$new_wl_item->date_added = current_time('timestamp');
				$new_wl_item->expires = strtotime('+1 hour', current_time('timestamp'));

				$cached_allowlist[$_GET['iphash']] = json_encode($new_wl_item);

				unset($cached_blocklist[$_GET['iphash']]);
				update_option('tinyshield_cached_allowlist', $cached_allowlist);
				update_option('tinyshield_cached_blocklist', $cached_blocklist);

?>
				<div class="updated"><p><strong><?php _e('The IP Address has added to the Allowlist.', 'tinyshield');?></strong></p></div>
<?php
			}
		}

		/*****************************************
			Delete IP Address from Allowlist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'remove_from_allowlist' && tinyShieldFunctions::is_sha1($_GET['iphash']) && wp_verify_nonce($_GET['_wpnonce'], 'tinyshield-delete-allowlist-item')){
			unset($cached_allowlist[$_GET['iphash']]);
			update_option('tinyshield_cached_allowlist', $cached_allowlist);
?>
			<div class="updated"><p><strong><?php _e('The IP Address has been removed from the Blocklist. If this IP is trys to connect to your site again, it will be rechecked.', 'tinyshield');?></strong></p></div>
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
					<a href="?page=tinyshield.php&tab=perm-allowlist" class="nav-tab <?php echo $active_tab == 'perm-allowlist' ? 'nav-tab-active' : ''; ?>">Permanent Allowlist (<?php echo count($cached_perm_allowlist); ?>)</a>
					<a href="?page=tinyshield.php&tab=perm-blocklist" class="nav-tab <?php echo $active_tab == 'perm-blocklist' ? 'nav-tab-active' : ''; ?>">Permanent Blocklist (<?php echo count($cached_perm_blocklist); ?>)</a>
					<a href="?page=tinyshield.php&tab=allowlist" class="nav-tab <?php echo $active_tab == 'allowlist' ? 'nav-tab-active' : ''; ?>">Allowlist (<?php echo count($cached_allowlist); ?>)</a>
					<a href="?page=tinyshield.php&tab=blocklist" class="nav-tab <?php echo $active_tab == 'blocklist' ? 'nav-tab-active' : ''; ?>">Blocklist (<?php echo count($cached_blocklist); ?>)</a>
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
									<p><input type="checkbox" name="activate[optin]" id="activate[optin]" checked /> <label for="activate[optin]"><?php _e('Can we contact you for marketing purposes?', 'tinyshield'); ?></label></p>


									<input type="hidden" name="activate[site]" value="<?php esc_attr_e(site_url()); ?>" />
									<p><input class="button button-primary" type="submit" name="activate-site" id="activate-site" value="<?php _e('Activate This Site', 'tinyshield'); ?>" /></p>

								<?php elseif(!is_null($options['subscription']) && $options['subscription'] != 'community'  && !empty($options['site_activation_key'])): ?>
									<p><input type="text" size="56" value="<?php _e($options['site_activation_key']); ?>" disabled /> 🎉 </p>
									<?php wp_nonce_field('tinyshield-deactivate-site'); ?>
									<input type="hidden" name="tinyshield_action" value="deactivate-site" />
									<p><input class="button button-secondary" type="submit" name="deactivate-site" id="deactivate-site" value="<?php _e('Deactivate This Site', 'tinyshield'); ?>" /></p>
								<?php else: ?>
									<p><input type="text" size="56" value="<?php _e('Your Site is Currently Activated with tinyShield'); ?>" disabled /> 😎 </p>
									<?php wp_nonce_field('tinyshield-deactivate-site'); ?>
									<input type="hidden" name="tinyshield_action" value="deactivate-site" />
									<p><input class="button button-secondary" type="submit" name="deactivate-site" id="deactivate-site" value="<?php _e('Deactivate This Site', 'tinyshield'); ?>" /></p>

								<?php endif; ?>
							</p>
						</form>

						<?php if(!is_null($options['subscription']) && $options['subscription'] == 'community' && !empty($options['site_activation_key'])): ?>
							<h3><?php _e('Upgrade To Professional', 'tinyshield'); ?></h3>
									<p><?php _e('Gain access to the most comprehensive blocklist and allowlist feeds we have to offer by signing up for our Professional service. Not only do you get access to our comprehensive feeds, you also support the project and gain access to premium support. Perfect for professional and commercial sites. Also note, professional features will not work, even if enabled, unless you have an active subscription.', 'tinyshield'); ?></p>
									<p><a target="_blank" href="<?php esc_attr_e(add_query_arg('site_activation_key', $options['site_activation_key'], self::$tinyshield_upgrade_url)); ?>" class="button button-primary"><?php _e('Upgrade This Site', 'tinyshield'); ?></a></p>
						<?php endif; ?>

						<hr />

						<h2 class="title"><?php _e('Options', 'tinyshield'); ?></h2>
						<form method="post" action="<?php echo esc_attr($_SERVER['REQUEST_URI']); ?>">
							<h3><?php _e('Pretty Deny', 'tinyshield'); ?></h3>
							<p>Toggle this to enable or disable presenting blocked visitors with a page explaining they've been blocked. Also gives the option to report false positives. If disabled, blocked visitors will be given a 403 Forbidden error with nothing else. <strong>Enabled by default.</strong></p>
							<p><input type="checkbox" name="options[pretty_deny]" id="options[pretty_deny]" <?php echo ($options['pretty_deny']) ? 'checked' : 'unchecked' ?> /> <label for="options[pretty_deny]"><?php _e('Pretty Deny?', 'tinyshield'); ?></label></p>

							<h3><?php _e('Report Failed Logins', 'tinyshield'); ?></h3>
							<p>Toggle this to enable or disable reporting failed logins to tinyShield. <strong>Enabled by default.</strong></p>
							<p><input type="checkbox" name="options[report_failed_logins]" id="options[report_failed_logins]" <?php echo ($options['report_failed_logins']) ? 'checked' : 'unchecked' ?> /> <label for="options[report_failed_logins]"><?php _e('Report Failed Logins?', 'tinyshield'); ?></label></p>

							<h3><?php _e('Report Spam Comments', 'tinyshield'); ?></h3>
							<p>Toggle this to enable or disable reporting spam comments. If enabled, this will report IPs of comments that you consider to be spam. Only occurs when you click the "spam" link under the comments section. <strong>Enabled by default.</strong></p>
							<p><input type="checkbox" name="options[report_spam_comments]" id="options[report_spam_comments]" <?php echo ($options['report_spam_comments']) ? 'checked' : 'unchecked' ?> /> <label for="options[report_spam_comments]"><?php _e('Report Spam Comments?', 'tinyshield'); ?></label></p>

							<h3><?php _e('Report User Registration', 'tinyshield'); ?></h3>
							<p>Toggle this to enable or disable reporting of user registration issues to tinyShield. We only send the IP address over to our servers for verification. Often times bots will try to register accounts to post spam or malicious links in posts. <strong>Enabled by default.</strong></p>
							<p><input type="checkbox" name="options[report_user_registration]" id="options[report_user_registration]" <?php echo ($options['report_user_registration']) ? 'checked' : 'unchecked' ?> /> <label for="options[report_user_registration]"><?php _e('Report User Registration?', 'tinyshield'); ?></label></p>

							<h3><?php _e('Report User Enumeration Attempts', 'tinyshield'); ?></h3>
							<p>Toggle this to enable or disable reporting user enumeration attempts to tinyShield. <strong>Enabled by default.</strong></p>
							<p><input type="checkbox" name="options[report_user_enumeration]" id="options[report_user_enumeration]" <?php echo ($options['report_user_enumeration']) ? 'checked' : 'unchecked' ?> /> <label for="options[report_user_enumeration]"><?php _e('Report User Enumeration Attempts?', 'tinyshield'); ?></label></p>

							<h3><?php _e('Enable the Registration Form honeypot?', 'tinyshield'); ?></h3>
							<p>Toggle this to enable or disable a hidden honeypot field on the user registration page. Spambots will often try to create fake users, this will help prevent that. <strong>Enabled by default.</strong></p>
							<p><input type="checkbox" name="options[registration_form_honeypot]" id="options[registration_form_honeypot]" <?php echo ($options['registration_form_honeypot']) ? 'checked' : 'unchecked' ?> /> <label for="options[registration_form_honeypot]"><?php _e('Registration Honeypot?', 'tinyshield'); ?></label></p>

							<h3><?php _e('Report 404', 'tinyshield'); ?></h3>
							<p>Toggle this to enable or disable reporting 404 requests to tinyShield. We do this to check for rapid succession 404s which will occur in scans of sites. <strong>Disabled by default.</strong></p>
							<p><input type="checkbox" name="options[report_404]" id="options[report_404]" <?php echo ($options['report_404']) ? 'checked' : 'unchecked' ?> /> <label for="options[report_404]"><?php _e('Report 404s?', 'tinyshield'); ?></label></p>

							<?php if($options['subscription'] != 'community'): ?>
								<h3><?php _e('Block Tor Exit Nodes - <i>Professional Feature</i>', 'tinyshield'); ?></h3>
								<p>Toggle this to enable or disable the blocking of <a href="https://www.torproject.org/" target="_blank">Tor</a> exit nodes. Tor can be used for malicious and legitimate purposes. If you have any reason anonymous users would access your site, leave this disabled. <strong>Disabled by default.</strong></p>
								<p><input type="checkbox" name="options[block_tor_exit_nodes]" id="options[block_tor_exit_nodes]" <?php echo ($options['block_tor_exit_nodes']) ? 'checked' : 'unchecked' ?> /> <label for="options[block_tor_exit_nodes]"><?php _e('Block Tor Exit Nodes?', 'tinyshield'); ?></label></p>

								<h3><?php _e('Inclusive Block Countries (GeoIP Filtering) - <i>Professional Feature</i>', 'tinyshield'); ?></h3>
								<p>Select a country or multiple countries to block from accessing your site. <strong>No countries are selected by default.</strong></p>
								<p>
									<?php
										$blocked_selected_countries = unserialize($options['countries_to_block']);
										$countries = tinyShieldFunctions::get_country_codes();
									?>

									<select class="country-select-block" multiple="multiple" name="options[countries_to_block][]" style="width: 50%">
										<option value=""></option>
										<?php foreach($countries as $code => $name): ?>
											<?php if(is_array($blocked_selected_countries) && in_array($code, $blocked_selected_countries)): ?>
												<option value="<?php esc_attr_e($code); ?>" selected> <?php esc_attr_e($name); ?></option>
											<?php else: ?>
												<option value="<?php esc_attr_e($code); ?>"> <?php esc_attr_e($name); ?></option>
											<?php endif; ?>
										<?php endforeach; ?>
									</select>
								</p>
							<?php endif; ?>

							<?php if($options['subscription'] != 'community'): ?>
								<h3><?php _e('Exclusive Block Countries (GeoIP Filtering) - <i>Professional Feature</i>', 'tinyshield'); ?></h3>
								<p>Select a country or multiple countries to allow access to your site assuming all countries are blocked by default. <strong>Feature disabled until a country is selected.</strong></p>
								<p>
									<?php
										$allowed_selected_countries = unserialize($options['countries_to_allow']);
										$countries = tinyShieldFunctions::get_country_codes();
									?>

									<select class="country-select-allow" multiple="multiple" name="options[countries_to_allow][]" style="width: 50%">
										<option value=""></option>
										<?php foreach($countries as $code => $name): ?>
											<?php if(is_array($allowed_selected_countries) && in_array($code, $allowed_selected_countries)): ?>
												<option value="<?php esc_attr_e($code); ?>" selected> <?php esc_attr_e($name); ?></option>
											<?php else: ?>
												<option value="<?php esc_attr_e($code); ?>"> <?php esc_attr_e($name); ?></option>
											<?php endif; ?>
										<?php endforeach; ?>
									</select>
								</p>
						<?php endif; ?>

							<h3><?php _e('Disable tinyShield', 'tinyshield'); ?></h3>
							<p>Toggle this to enable or disable the core functionality of this plugin. It is <strong>NOT</strong> recommended to disable tinyShield and if you must, do only for testing purposes. <strong>Disabled by default.</strong></p>
							<p><input type="checkbox" name="options[tinyshield_disabled]" id="options[tinyshield_disabled]" <?php echo ($options['tinyshield_disabled']) ? 'checked' : 'unchecked' ?> /> <label for="options[tinyshield_disabled]"><?php _e('Disable tinyShield?', 'tinyshield'); ?></label></p>

							<div class="submit">
								<?php wp_nonce_field('tinyshield-update-options'); ?>
								<input type="hidden" name="tinyshield_action" value="options_save" />
								<input type="hidden" name="options[subscription]" value="<?php (!empty($options['subscription']) ? esc_attr_e($options['subscription']): ''); ?>" />
								<input type="hidden" name="options[site_activation_key]" value="<?php (!empty($options['site_activation_key']) ? esc_attr_e($options['site_activation_key']) : ''); ?>" />

								<input type="submit" class="button button-primary" name="tinyshield_save_options" value="<?php _e('Save Settings', 'tinyshield') ?>" />
							</div>
						</form>

						<hr />

						<h2 class="title"><?php _e('Diagnostics', 'tinyshield'); ?></h2>
						<h3><?php _e('Clear Cached Blocklist', 'tinyshield'); ?></h3>

						<form method="post" action="<?php echo esc_attr($_SERVER['REQUEST_URI']); ?>">
							<p>Use this to clear all addresses from your local cached blocklist. This is not recommended and only use in case of issues or if directed by support.</p>
							<?php wp_nonce_field('tinyshield-clear-local-blocklist'); ?>
							<input type="hidden" name="tinyshield_action" value="clear_cached_blocklist" />
							<p><input class="button button-secondary" type="submit" name="clear_cached_blocklist" id="clear_cached_blocklist" value="<?php _e('Clear Cache Blocklist', 'tinyshield'); ?>" /></p>
						</form>

						<h3><?php _e('Clear Cached Allowlist', 'tinyshield'); ?></h3>

						<form method="post" action="<?php echo esc_attr($_SERVER['REQUEST_URI']); ?>">
							<p>Use this to clear all addresses from your local cached allowlist. This is not recommended and only use in case of issues or if directed by support.</p>
							<?php wp_nonce_field('tinyshield-clear-local-allowlist'); ?>
							<input type="hidden" name="tinyshield_action" value="clear_cached_allowlist" />
							<p><input class="button button-secondary" type="submit" name="clear_cached_allowlist" id="clear_cached_allowlist" value="<?php _e('Clear Cache Allowlist', 'tinyshield'); ?>" /></p>
						</form>

						<h3><?php _e('Clear Permanent Blocklist', 'tinyshield'); ?></h3>

						<form method="post" action="<?php echo esc_attr($_SERVER['REQUEST_URI']); ?>">
							<p>Use this to clear all addresses from your permanent blocklist. This is not recommended and only use in case of issues or if directed by support.</p>
							<?php wp_nonce_field('tinyshield-clear-permanent-blocklist'); ?>
							<input type="hidden" name="tinyshield_action" value="clear_permanent_blocklist" />
							<p><input class="button button-secondary" type="submit" name="clear_permanent_blocklist" id="clear_permanent_blocklist" value="<?php _e('Clear Permanent Blocklist', 'tinyshield'); ?>" /></p>
						</form>

				<?php endif; ?>

				<!--
						**********************************
							permanent blocklist table
						**********************************
				-->
				<?php if($active_tab == 'perm-blocklist'): ?>
					<form method="post" action="<?php echo esc_url(remove_query_arg(array('action', '_wpnonce', 'iphash'), $_SERVER['REQUEST_URI'])); ?>">
						<?php
							if(function_exists('wp_nonce_field')){
								wp_nonce_field('update-tinyshield-perm-blocklist');
								$delete_item_nonce = wp_create_nonce('delete-tinyshield-perm-blocklist-item');
							}
						?>
						<h3>Permanent Blocklist</h3>
						<p>These are addresses that are permanently blocked from accessing the site regardless if they are found in a blocklist or not.</p>
						<hr />
						<p>
							<textarea name="perm_ip_to_blocklist" rows="5" cols="60" placeholder="<?php _e('Enter a single or multiple IP addresses. One address per line.', 'tinyshield'); ?>"></textarea>
						</p>
						<p>
							<input type="submit" class="button button-primary" name="tinyshield_perm_blocklist_update" value="<?php _e('Add to Blocklist', 'tinyshield') ?>" />
						</p>

					</form>
					<?php
						$tinyShield_PermBlockList_Table = new tinyShield_PermBlockList_Table();
						$tinyShield_PermBlockList_Table->prepare_items();
					?>
					<form id="perm-blocklist-table" method="get">
						<input type="hidden" name="page" value="<?php echo absint($_REQUEST['page']); ?>" />
						<?php $tinyShield_PermBlockList_Table->display(); ?>
					</form>
				<?php endif; ?>

				<!--
						**********************************
							permanent allowlist table
						**********************************
				-->

				<?php if($active_tab == 'perm-allowlist'): ?>
					<form method="post" action="<?php echo esc_url(remove_query_arg(array('action', '_wpnonce', 'iphash'), $_SERVER['REQUEST_URI'])); ?>">
						<?php
							if(function_exists('wp_nonce_field')){
								wp_nonce_field('update-tinyshield-perm-allowlist');
								$delete_item_nonce = wp_create_nonce('delete-tinyshield-perm-allowlist-item');
							}
						?>
						<h3>Permanent Allowlist</h3>
						<p>These are addresses that are permanently allowed to access the site even if they are found in a blocklist. This is useful for false positives. The permanent allowlist is checked before any other check is performed.</p>
						<hr />
						<p>
							<textarea name="perm_ip_to_allowlist" rows="5" cols="60" placeholder="<?php _e('Enter a single or multiple IP addresses. One address per line.', 'tinyshield'); ?>"></textarea>
						</p>
						<p>
							<input type="submit" class="button button-primary" name="tinyshield_perm_allowlist_update" value="<?php _e('Add to Allowlist', 'tinyshield') ?>" />
						</p>
					</form>
					<?php
						$tinyShield_PermAllowlist_Table = new tinyShield_PermAllowlist_Table();
						$tinyShield_PermAllowlist_Table->prepare_items();
					?>
					<form id="perm-allowlist-table" method="get">
						<input type="hidden" name="page" value="<?php echo absint($_REQUEST['page']); ?>" />
						<?php $tinyShield_PermAllowlist_Table->display(); ?>
					</form>
			  <?php endif; ?>
				<?php if($active_tab == 'allowlist'): ?>
					<h3>Allowlist</h3>
					<p>These are addresses that have been checked and are not known to be malicious at this time. Addresses will remain cached for 1 hour and then will be checked again.</p>
					<hr />
					<?php
						$tinyShield_Allowlist_Table = new tinyShield_Allowlist_Table();
						$tinyShield_Allowlist_Table->prepare_items();
					?>
					<form id="allowlist-table" method="get">
						<input type="hidden" name="page" value="<?php echo absint($_REQUEST['page']); ?>" />
						<?php $tinyShield_Allowlist_Table->display(); ?>
					</form>
			  <?php endif; ?>
				<!--
						**********************************
							blocklist table
						**********************************
				-->
				<?php if($active_tab == 'blocklist'): ?>
					<h3>Blocklist</h3>
					<p>These are addresses that have tried to visit your site and been found to be malicious. Requests from these addresses are blocked and will remain cached for 24 hours and then will be checked again.</p>
					<hr />
					<?php
						$tinyShield_BlockList_Table = new tinyShield_BlockList_Table();
						$tinyShield_BlockList_Table->prepare_items();
					?>
					<form id="blocklist-table" method="get">
						<input type="hidden" name="page" value="<?php echo absint($_REQUEST['page']); ?>" />
						<?php $tinyShield_BlockList_Table->display(); ?>
					</form>
				<?php endif; ?>

			</div> <!--end div -->
<?php
	}
} //End tinyShield Class

$tinyShield = new tinyShield();
