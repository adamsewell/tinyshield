<?php
  class tinyShield_Admin extends tinyShield{

    public static function add_additional_links($actions){
      $additional_links = array(
        '<a href="' . esc_url(admin_url('admin.php?page=tinyshield.php&tab=settings')) . '">' . __('Settings', 'tinyshield') . '</a>',
        '<a target="_blank" href="' . esc_url(self::$tinyshield_account_url) . '">' . __('Manage tinyShield Account', 'tinyshield') . '</a>',
      );

      $actions = array_merge($actions, $additional_links);
      return $actions;
    }

    public static function register_admin_resources($page){
      if($page == 'toplevel_page_tinyshield' || $page == 'index.php'){
        $options = get_option('tinyshield_options');

        wp_enqueue_script('select2', self::$plugin_dir_url . 'lib/js/select2.min.js', array('jquery'), '4.0.13', true);
        wp_enqueue_script('chartjs', 'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.5.1/chart.min.js', array(), '3.5.1');
        wp_enqueue_script('tinyshield-custom', self::$plugin_dir_url . 'lib/js/tinyshield.custom.js', array('jquery', 'select2'), time(), true);

        wp_enqueue_style('tinyshield-select2-css', self::$plugin_dir_url . 'lib/css/select2.min.css');
        wp_enqueue_style('tinyshield-css', self::$plugin_dir_url . 'lib/css/tinyshield.css');

        $stats = unserialize($options['tinyshield_stats']);

        wp_localize_script('tinyshield-custom', 'tinyshield', array(
          'nonce' => wp_create_nonce('tinyshield-nonce'),
          'data' => array(
              'allowed' => array(
                (!empty($stats['allowed'][strtotime('-6 days', strtotime('today'))]) ? absint($stats['allowed'][strtotime('-6 days', strtotime('today'))]) : 0),
                (!empty($stats['allowed'][strtotime('-5 days', strtotime('today'))]) ? absint($stats['allowed'][strtotime('-5 days', strtotime('today'))]) : 0),
                (!empty($stats['allowed'][strtotime('-4 days', strtotime('today'))]) ? absint($stats['allowed'][strtotime('-4 days', strtotime('today'))]) : 0),
                (!empty($stats['allowed'][strtotime('-3 days', strtotime('today'))]) ? absint($stats['allowed'][strtotime('-3 days', strtotime('today'))]) : 0),
                (!empty($stats['allowed'][strtotime('-2 days', strtotime('today'))]) ? absint($stats['allowed'][strtotime('-2 days', strtotime('today'))]) : 0),
                (!empty($stats['allowed'][strtotime('yesterday')]) ? absint($stats['allowed'][strtotime('yesterday')]) : 0),
                (!empty($stats['allowed'][strtotime('today')]) ? absint($stats['allowed'][strtotime('today')]) : 0),
              ),
              'blocked' => array(
                (!empty($stats['blocked'][strtotime('-6 days', strtotime('today'))]) ? absint($stats['blocked'][strtotime('-6 days', strtotime('today'))]) : 0),
                (!empty($stats['blocked'][strtotime('-5 days', strtotime('today'))]) ? absint($stats['blocked'][strtotime('-5 days', strtotime('today'))]) : 0),
                (!empty($stats['blocked'][strtotime('-4 days', strtotime('today'))]) ? absint($stats['blocked'][strtotime('-4 days', strtotime('today'))]) : 0),
                (!empty($stats['blocked'][strtotime('-3 days', strtotime('today'))]) ? absint($stats['blocked'][strtotime('-3 days', strtotime('today'))]) : 0),
                (!empty($stats['blocked'][strtotime('-2 days', strtotime('today'))]) ? absint($stats['blocked'][strtotime('-2 days', strtotime('today'))]) : 0),
                (!empty($stats['blocked'][strtotime('yesterday')]) ? absint($stats['blocked'][strtotime('yesterday')]) : 0),
                (!empty($stats['blocked'][strtotime('today')]) ? absint($stats['blocked'][strtotime('today')]) : 0),
              )

          ),
          'labels' => array(
            wp_date(get_option('date_format'), strtotime('-6 days', strtotime('today'))),
            wp_date(get_option('date_format'), strtotime('-5 days', strtotime('today'))),
            wp_date(get_option('date_format'), strtotime('-4 days', strtotime('today'))),
            wp_date(get_option('date_format'), strtotime('-3 days', strtotime('today'))),
            wp_date(get_option('date_format'), strtotime('-2 days', strtotime('today'))),
            wp_date(get_option('date_format'), strtotime('yesterday')),
            wp_date(get_option('date_format'), strtotime('today')),
          ),
        ));
      }
    }

    public static function acknowledge_admin_notice(){
      if(isset($_GET['dismiss_tinyshield_nag']) && $_GET['dismiss_tinyshield_nag'] == '1'){
        add_user_meta(get_current_user_id(), 'tinyshield_review_notice', 'true', true);
      }
    }

    public static function add_menu(){
      if(function_exists('add_menu_page')){
        add_menu_page('tinyShield', 'tinyShield', 'manage_options', self::$plugin_basename, 'tinyShield_Admin::display_options', self::$plugin_dir_url . 'img/tinyshield.png');
        add_submenu_page(self::$plugin_basename, 'tinyShield', 'Activity Log', 'manage_options', self::$plugin_basename, 'tinyShield_Admin::display_options');
        add_submenu_page(self::$plugin_basename, 'Permanent Allowlist', 'Permanent Allowlist', 'manage_options', 'tinyshield.php&tab=perm-allowlist', 'tinyShield_Admin::display_options');
        add_submenu_page(self::$plugin_basename, 'Permanent Blocklist', 'Permanent Blocklist', 'manage_options', 'tinyshield.php&tab=perm-blocklist', 'tinyShield_Admin::display_options');
        add_submenu_page(self::$plugin_basename, 'Allowlist', 'Allowlist', 'manage_options', 'tinyshield.php&tab=allowlist', 'tinyShield_Admin::display_options');
        add_submenu_page(self::$plugin_basename, 'Blocklist', 'Blocklist', 'manage_options', 'tinyshield.php&tab=blocklist', 'tinyShield_Admin::display_options');
        add_submenu_page(self::$plugin_basename, 'Settings', 'Settings', 'manage_options', 'tinyshield.php&tab=settings', 'tinyShield_Admin::display_options');
        add_submenu_page(self::$plugin_basename, 'Activation', 'Activation', 'manage_options', 'tinyshield.php&tab=activation', 'tinyShield_Admin::display_options');
        add_submenu_page(self::$plugin_basename, 'Diagnostics', 'Diagnostics', 'manage_options', 'tinyshield.php&tab=diagnostics', 'tinyShield_Admin::display_options');
      }
    }

    public static function notices(){
      $options = get_option('tinyshield_options');
  ?>
      <?php if(current_user_can('manage_options') && empty($options['site_activation_key'])): ?>
        <style>
            p.error {
                position: relative;
                margin-left: 35px;
                padding: 1px;
            }

            p.error span.dashicons-bell {
                color: white;
                background: #d63638;
                position: absolute;
                left: -50px;
                padding: 9px;
                top: -8px;
            }

            p.error strong {
                color: #d63638;
            }

            p.error a.dismiss {
                float: right;
                text-decoration: none;
                color: #d63638;
            }
        </style>

        <div class="notice notice-error"><p class="error"><span class="dashicons dashicons-bell"></span><strong><?php _e('tinyShield: tinyShield is not currently activated. Before we can help protect your site, you must register your site. You can do that here <a href="' . esc_url(admin_url('admin.php?page=tinyshield.php&tab=activation')) . '">tinyShield Activation</a>.', 'tinyshield'); ?> </strong></p></div>
      <?php endif; ?>

      <?php if(current_user_can('manage_options') && !empty($options['license_error'])): ?>
        <style>
            p.error {
                position: relative;
                margin-left: 35px;
                padding: 1px;
            }

            p.error span.dashicons-bell {
                color: white;
                background: #d63638;
                position: absolute;
                left: -50px;
                padding: 9px;
                top: -8px;
            }

            p.error strong {
                color: #d63638;
            }

            p.error a.dismiss {
                float: right;
                text-decoration: none;
                color: #d63638;
            }
        </style>
        <div class="notice notice-error"><p class="error"><span class="dashicons dashicons-bell"></span><strong><?php _e('tinyShield: tinyShield has reported an issue with your license key. Traffic is not being analyzed. Check your activation here <a href="' . esc_url(admin_url('admin.php?page=tinyshield.php&tab=activation')) . '">tinyShield Settings</a>. Try deactivating and reactivating first, but contact support if needed.', 'tinyshield');?> </strong></p></div>
      <?php endif; ?>

      <?php if(current_user_can('manage_options') && $options['tinyshield_disabled']): ?>
        <style>
            p.warning {
                position: relative;
                margin-left: 35px;
                padding: 1px;
            }

            p.warning span.dashicons-bell {
                color: white;
                background: #dba617;
                position: absolute;
                left: -50px;
                padding: 9px;
                top: -8px;
            }

            p.warning strong {
                color: #dba617;
            }

            p.warning a.dismiss {
                float: right;
                text-decoration: none;
                color: #dba617;
            }
        </style>

        <div class="notice notice-warning"><p class="warning"><span class="dashicons dashicons-bell"></span><strong><?php _e('tinyShield: tinyShield is currently disabled and not protecting your site. To re-enable tinyShield, you can do that under the options here <a href="' . esc_url(admin_url('admin.php?page=tinyshield.php&tab=settings')) . '">tinyShield Settings</a> under Options.', 'tinyshield');?></strong></p></div>
      <?php endif; ?>

      <?php if(current_user_can('manage_options') && !is_null($options['subscription']) && $options['subscription'] == 'community' && $options['review_date'] <= time() && empty(get_user_meta(get_current_user_id(), 'tinyshield_review_notice'))): ?>
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
          $nag_admin_dismiss_url = admin_url("admin.php?page=tinyshield.php&tab=" . $active_tab . "&dismiss_tinyshield_nag=1");
          $plugin_review_url = "https://wordpress.org/support/plugin/tinyshield/reviews/#new-post";
        ?>
        <div class="notice notice-success"><p class="review"><span class="dashicons dashicons-heart"></span><strong><?php _e('tinyShield: Are you seeing benefit out of tinyShield? Consider <a href="' . esc_url(admin_url('admin.php?page=tinyshield.php&tab=activation')) . '">upgrading to premium access</a> for lots of additional features or consider leaving us a <a target="_blank" href="' . esc_url($plugin_review_url) . '">plugin review</a>!'); ?> <a href="<?php echo esc_url($nag_admin_dismiss_url); ?>" class="dismiss"><span class="dashicons dashicons-dismiss"></span></a></strong></p></div>
      <?php endif; ?>
  <?php
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
        'key_not_found' => __('Sorry, this key was not found. Please deactivate and try again or contact support.', 'tinyshield'),
        'key_in_use' => __('Sorry, this site has already been activated. Please contact support.', 'tinyshield'),
        'key_expired' => __('This key is expired. Please renew your key.', 'tinyshield'),
        'key_banned' => __('This key has been banned.', 'tinyshield'),
        'something_went_wrong' => __('Something went wrong but we\'re not sure what...', 'tinyshield'),
        'missing_registration_data' => __('You must provide your first name, last name, and email address to register your site.', 'tinyshield'),
        'ip_could_not_be_found' => __('The IP could not be found.', 'tinyshield'),
        'development_site' => __('tinyShield should not be activated on a development site. It does not function properly. Activate once live or on a low traffic site.', 'tinyshield')
      );

      /*****************************************
          Settings Page Update
      *****************************************/
      if(isset($_POST['tinyshield_save_options']) && $_POST['tinyshield_action'] == 'options_save' && wp_verify_nonce($_POST['_wpnonce'], 'tinyshield-update-options')) {
        if(is_array($_POST['options']) && !empty($_POST['options'])){
          foreach($options as $key => $value){
            if(array_key_exists($key, $_POST['options'])){
              if(is_null($_POST['options'][$key]) || empty($_POST['options'][$key])){
                $options[$key] = false;
              }elseif(is_array($_POST['options'][$key]) || is_object($_POST['options'][$key])){
                $options[$key] = serialize($_POST['options'][$key]);
              }elseif(filter_var($_POST['options'][$key], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) === true){
                $options[$key] = true;
              }elseif(filter_var($_POST['options'][$key], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) === false){
                $options[$key] = false;
              }else{
                $options[$key] = filter_var($_POST['options'][$key], FILTER_SANITIZE_STRING);
              }
            }elseif($value === true && array_key_exists($key, $_POST['options']) === false){
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
            'fname' => filter_var($_POST['activate']['fname'], FILTER_SANITIZE_STRING),
            'lname' => filter_var($_POST['activate']['lname'], FILTER_SANITIZE_STRING),
            'email' => filter_var($_POST['activate']['email'], FILTER_SANITIZE_EMAIL),
            'optin' => filter_var($_POST['activate']['optin'], FILTER_SANITIZE_STRING),
            'association_key' => filter_var($_POST['activate']['association_key'], FILTER_SANITIZE_STRING),
            'site' => esc_url_raw($_POST['activate']['site'])
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

        $maybe_deactivate = tinyShieldFunctions::deactivate_site($registration_data);

        if(is_bool($maybe_deactivate) && $maybe_deactivate){
          $options['subscription'] = '';
          $options['site_activation_key'] = '';
          $options['license_error'] = false;
          update_option('tinyshield_options', $options);
          $alerts = $success_messages['site_key_deactivated'];

        }else{
          $errors = $error_messages['something_went_wrong'];
        }
      }

      /*****************************************
        Handle clearing of local blocklist
      *****************************************/
      if(isset($_POST['tinyshield_action']) && $_POST['tinyshield_action'] == 'clear_cached_blocklist' && wp_verify_nonce($_POST['_wpnonce'], 'tinyshield-clear-local-blocklist')){
        $cached_blocklist = get_option('tinyshield_cached_blocklist');

        foreach($cached_blocklist as $iphash => $iphash_data){
            do_action('tinyshield_blocklist_clear_ip', $iphash);
        }

        $cached_blocklist = array();
        update_option('tinyshield_cached_blocklist', $cached_blocklist);

        $alerts = $success_messages['blocklist_cleared'];
      }

      /*****************************************
        Handle clearing of local allowlist
      *****************************************/
      if(isset($_POST['tinyshield_action']) && $_POST['tinyshield_action'] == 'clear_cached_allowlist' && wp_verify_nonce($_POST['_wpnonce'], 'tinyshield-clear-local-allowlist')){
        $cached_allowlist = get_option('tinyshield_cached_allowlist');

        foreach($cached_allowlist as $iphash => $iphash_data){
            do_action('tinyshield_allowlist_clear_ip', $iphash);
        }

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
            tinyShield::$tinyshield_report_url,
            array(
              'body' => array(
                'ip_to_report' => $ip_to_report,
                'type' => 'report_false_positive',
                'reporting_site' => site_url(),
                'time_of_occurance' => time()
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
              $perm_allowlist_entry->expires = strtotime('+30 years', time());
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
              $perm_blocklist_entry->expires = strtotime('+30 years', time());
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
          $new_bl_item->date_added = time();
          $new_bl_item->expires = strtotime('+24 hours', time());

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
        do_action('tinyshield_blocklist_clear_ip', $_GET['iphash']);

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
          $new_wl_item->date_added = time();
          $new_wl_item->expires = strtotime('+1 hour', time());

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
            <a href="<?php echo esc_url(admin_url('admin.php?page=tinyshield.php&tab=log')); ?>" class="nav-tab <?php echo $active_tab == 'log' ? 'nav-tab-active' : ''; ?>"><?php _e('Activity Log', 'tinyshield'); ?></a>
            <a href="<?php echo esc_url(admin_url('admin.php?page=tinyshield.php&tab=perm-allowlist')); ?>" class="nav-tab <?php echo $active_tab == 'perm-allowlist' ? 'nav-tab-active' : ''; ?>"><?php _e('Permanent Allowlist', 'tinyshield'); ?> (<?php echo absint(count($cached_perm_allowlist)); ?>)</a>
            <a href="<?php echo esc_url(admin_url('admin.php?page=tinyshield.php&tab=perm-blocklist')); ?>" class="nav-tab <?php echo $active_tab == 'perm-blocklist' ? 'nav-tab-active' : ''; ?>"><?php _e('Permanent Blocklist', 'tinyshield'); ?> (<?php echo absint(count($cached_perm_blocklist)); ?>)</a>
            <a href="<?php echo esc_url(admin_url('admin.php?page=tinyshield.php&tab=allowlist')); ?>" class="nav-tab <?php echo $active_tab == 'allowlist' ? 'nav-tab-active' : ''; ?>"><?php _e('Allowlist', 'tinyshield'); ?> (<?php echo absint(count($cached_allowlist)); ?>)</a>
            <a href="<?php echo esc_url(admin_url('admin.php?page=tinyshield.php&tab=blocklist')); ?>" class="nav-tab <?php echo $active_tab == 'blocklist' ? 'nav-tab-active' : ''; ?>"><?php _e('Blocklist', 'tinyshield'); ?> (<?php echo absint(count($cached_blocklist)); ?>)</a>
            <a href="<?php echo esc_url(admin_url('admin.php?page=tinyshield.php&tab=settings')); ?>" class="nav-tab <?php echo $active_tab == 'settings' ? 'nav-tab-active' : ''; ?>"><?php _e('Settings', 'tinyshield'); ?></a>
            <a href="<?php echo esc_url(admin_url('admin.php?page=tinyshield.php&tab=activation')); ?>" class="nav-tab <?php echo $active_tab == 'activation' ? 'nav-tab-active' : ''; ?>"> <?php _e('Activation', 'tinyshield'); ?></a>
            <a href="<?php echo esc_url(admin_url('admin.php?page=tinyshield.php&tab=diagnostics')); ?>" class="nav-tab <?php echo $active_tab == 'diagnostics' ? 'nav-tab-active' : ''; ?>"> <?php _e('Diagnostics', 'tinyshield'); ?></a>
          </h2>

          <!--
              **********************************
               activity log
              **********************************
          -->

          <?php if($active_tab == 'log'): ?>
            <form method="post" action="<?php echo esc_attr($_SERVER['REQUEST_URI']); ?>">
              <h3><?php _e('Activity Log', 'tinyshield'); ?></h3>
              <p><?php _e('View the latest traffic to your site and how it was dealt with by tinyShield. Reporting a false positive will submit the offending IP to tinyShield for further review.', 'tinyshield'); ?></p>
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
                activation
              **********************************
          -->
          <?php if($active_tab == 'activation'): ?>

              <h2 class="title"><?php _e('Site Activation', 'tinyshield'); ?></h2>
              <p style="font-size: medium;"><strong><?php _e('Returning user or want to manage your account? See <a target="_blank" href="' . esc_url(self::$tinyshield_account_url) . '">your tinyShield account</a>.', 'tinyshield'); ?></strong></p>
              <h3><?php _e('Activation Key', 'tinyshield'); ?></h3>

              <form method="post" action="<?php echo esc_attr($_SERVER['REQUEST_URI']); ?>">
                <p>
                  <?php if(empty($options['site_activation_key'])): ?>
                    <p><?php _e('Before we can help protect your site, you must register and activate your site with tinyShield. If you have already purchased a license, you can find it on the <a target="_blank" href="' . esc_url(self::$tinyshield_account_url) . '">tinyShield account</a> page then copy the key and paste in the license key field below.', 'tinyshield'); ?></p>
                    <?php wp_nonce_field('tinyshield-activate-site'); ?>
                    <input type="hidden" name="tinyshield_action" value="activate-site" />

                    <p>
                      <input size="28" type="text" placeholder="<?php _e('Contact First Name', 'tinyshield'); ?>" name="activate[fname]" value="" />
                      <input size="28" type="text" placeholder="<?php _e('Contact Last Name', 'tinyshield'); ?>" name="activate[lname]" value="" />
                    </p>
                    <p><input size="56" type="text" placeholder="<?php _e('Contact Email Address', 'tinyshield'); ?>" name="activate[email]" value="" /></p>
                    <p><input size="56" type="text" placeholder="<?php _e('License Key (For Agencies or Multiple Sites)', 'tinyshield'); ?>" name="activate[association_key]" value="" /></p>
                    <p><input type="checkbox" name="activate[optin]" id="activate[optin]" checked /> <label for="activate[optin]"><?php _e('Would you like to be notified of product updates and marketing via email?', 'tinyshield'); ?></label></p>


                    <input type="hidden" name="activate[site]" value="<?php esc_attr_e(site_url()); ?>" />
                    <p><input class="button button-primary" type="submit" name="activate-site" id="activate-site" value="<?php _e('Activate This Site', 'tinyshield'); ?>" /></p>

                  <?php elseif(!is_null($options['subscription']) && $options['subscription'] != 'community'  && !empty($options['site_activation_key'])): ?>
                    <p><input type="text" size="56" value="<?php _e($options['site_activation_key']); ?>" disabled /> 🎉 </p>
                    <?php wp_nonce_field('tinyshield-deactivate-site'); ?>
                    <input type="hidden" name="tinyshield_action" value="deactivate-site" />
                    <p><input class="button button-secondary" type="submit" name="deactivate-site" id="deactivate-site" value="<?php _e('Deactivate This Site', 'tinyshield'); ?>" /></p>
                  <?php else: ?>
                    <p><input type="text" size="56" value="<?php _e($options['site_activation_key']); ?>" disabled /> 😎 </p>
                    <?php wp_nonce_field('tinyshield-deactivate-site'); ?>
                    <input type="hidden" name="tinyshield_action" value="deactivate-site" />
                    <p><input class="button button-secondary" type="submit" name="deactivate-site" id="deactivate-site" value="<?php _e('Deactivate This Site', 'tinyshield'); ?>" /></p>

                  <?php endif; ?>
                </p>
              </form>

              <?php if(!is_null($options['subscription']) && $options['subscription'] == 'community' && !empty($options['license_id']) && !empty($options['site_activation_key'])): ?>
                <h3><?php _e('Upgrade To Premium Access', 'tinyshield'); ?></h3>
                    <p><?php _e('Gain access to the most comprehensive blocklist and allowlist feeds we have to offer by signing up for Premium Access. Not only do you get access to our comprehensive feeds and support for multiple sites, you also support the project and gain access to premium support. Perfect for professional and commercial sites. Also note: premium features will not work (even if enabled) unless you have an active subscription.', 'tinyshield'); ?></p>
                    <p>
                      <a target="_blank" href="<?php echo esc_url(
                        add_query_arg(array(
                          'edd_action' => 'sl_license_upgrade',
                          'license_id' => absint($options['license_id']),
                          'upgrade_id' => 3
                        ),
                        self::$tinyshield_upgrade_url)); ?>" class="button button-primary"><?php _e('Personal Plan - One Site', 'tinyshield'); ?>
                      </a>
                      <a target="_blank" href="<?php echo esc_url(
                        add_query_arg(array(
                          'edd_action' => 'sl_license_upgrade',
                          'license_id' => absint($options['license_id']),
                          'upgrade_id' => 1
                        ),
                        self::$tinyshield_upgrade_url)); ?>" class="button button-primary"><?php _e('Professional - Up to Five Sites', 'tinyshield'); ?>
                      </a>
                      <a target="_blank" href="<?php echo esc_url(
                        add_query_arg(array(
                          'edd_action' => 'sl_license_upgrade',
                          'license_id' => absint($options['license_id']),
                          'upgrade_id' => 2
                        ),
                        self::$tinyshield_upgrade_url)); ?>" class="button button-primary"><?php _e('Agency - Unlimited Sites', 'tinyshield'); ?>
                      </a>
                    </p>
              <?php endif; ?>

            <?php endif; ?>

            <?php if($active_tab == 'diagnostics'): ?>

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

            <?php if($active_tab == 'settings'): ?>

              <h2 class="title"><?php _e('Options', 'tinyshield'); ?></h2>
              <form method="post" action="<?php echo esc_attr($_SERVER['REQUEST_URI']); ?>">
                <h3><?php _e('Pretty Deny', 'tinyshield'); ?></h3>
                <p>Toggle this to enable or disable presenting blocked visitors with a page explaining they've been blocked. Also gives the option to report false positives. If disabled, blocked visitors will be given a 403 Forbidden error with nothing else. <strong><?php _e('Enabled by default.', 'tinyshield'); ?></strong></p>
                <p><input type="checkbox" name="options[pretty_deny]" id="options[pretty_deny]" <?php echo ($options['pretty_deny']) ? 'checked' : 'unchecked' ?> /> <label for="options[pretty_deny]"><?php _e('Pretty Deny?', 'tinyshield'); ?></label></p>

                <h3><?php _e('Report Failed Logins', 'tinyshield'); ?></h3>
                <p>Toggle this to enable or disable reporting failed logins to tinyShield. <strong><?php _e('Enabled by default.', 'tinyshield'); ?></strong></p>
                <p><input type="checkbox" name="options[report_failed_logins]" id="options[report_failed_logins]" <?php echo ($options['report_failed_logins']) ? 'checked' : 'unchecked' ?> /> <label for="options[report_failed_logins]"><?php _e('Report Failed Logins?', 'tinyshield'); ?></label></p>

                <h3><?php _e('Brute Force Protection', 'tinyshield'); ?></h3>
                <p>Toggle this to enable or disable automatic brute force protection. Will automatically block IP addresses that fail to login successfully after 10 tries in a 24 hour period. <strong><?php _e('Enabled by default.', 'tinyshield'); ?></strong></p>
                <p><input type="checkbox" name="options[brute_force_protection]" id="options[brute_force_protection]" <?php echo ($options['brute_force_protection']) ? 'checked' : 'unchecked' ?> /> <label for="options[brute_force_protection]"><?php _e('Enable Brute Force Protection?', 'tinyshield'); ?></label></p>


                <h3><?php _e('Report Spam Comments', 'tinyshield'); ?></h3>
                <p>Toggle this to enable or disable reporting spam comments. If enabled, this will report IPs of comments that you consider to be spam. Only occurs when you click the "spam" link under the comments section. <strong><?php _e('Enabled by default.', 'tinyshield'); ?></strong></p>
                <p><input type="checkbox" name="options[report_spam_comments]" id="options[report_spam_comments]" <?php echo ($options['report_spam_comments']) ? 'checked' : 'unchecked' ?> /> <label for="options[report_spam_comments]"><?php _e('Report Spam Comments?', 'tinyshield'); ?></label></p>

                <h3><?php _e('Report User Registration', 'tinyshield'); ?></h3>
                <p>Toggle this to enable or disable reporting of user registration issues to tinyShield. We only send the IP address over to our servers for verification. Often times bots will try to register accounts to post spam or malicious links in posts. <strong><?php _e('Enabled by default.', 'tinyshield'); ?></strong></p>
                <p><input type="checkbox" name="options[report_user_registration]" id="options[report_user_registration]" <?php echo ($options['report_user_registration']) ? 'checked' : 'unchecked' ?> /> <label for="options[report_user_registration]"><?php _e('Report User Registration?', 'tinyshield'); ?></label></p>

                <h3><?php _e('Report User Enumeration Attempts', 'tinyshield'); ?></h3>
                <p>Toggle this to enable or disable reporting user enumeration attempts to tinyShield. <strong><?php _e('Enabled by default.', 'tinyshield'); ?></strong></p>
                <p><input type="checkbox" name="options[report_user_enumeration]" id="options[report_user_enumeration]" <?php echo ($options['report_user_enumeration']) ? 'checked' : 'unchecked' ?> /> <label for="options[report_user_enumeration]"><?php _e('Report User Enumeration Attempts?', 'tinyshield'); ?></label></p>

                <h3><?php _e('Enable the Registration Form honeypot?', 'tinyshield'); ?></h3>
                <p>Toggle this to enable or disable a hidden honeypot field on the user registration page. Spambots will often try to create fake users, this will help prevent that. <strong><?php _e('Enabled by default.', 'tinyshield'); ?></strong></p>
                <p><input type="checkbox" name="options[registration_form_honeypot]" id="options[registration_form_honeypot]" <?php echo ($options['registration_form_honeypot']) ? 'checked' : 'unchecked' ?> /> <label for="options[registration_form_honeypot]"><?php _e('Registration Honeypot?', 'tinyshield'); ?></label></p>

                <h3><?php _e('Report 404', 'tinyshield'); ?></h3>
                <p>Toggle this to enable or disable reporting 404 requests to tinyShield. We do this to check for rapid succession 404s which will occur in scans of sites. <strong>Disabled by default.</strong></p>
                <p><input type="checkbox" name="options[report_404]" id="options[report_404]" <?php echo ($options['report_404']) ? 'checked' : 'unchecked' ?> /> <label for="options[report_404]"><?php _e('Report 404s?', 'tinyshield'); ?></label></p>

                <?php if($options['subscription'] != 'community'): ?>
                  <h3><?php _e('Block Tor Exit Nodes - <i>Premium Feature</i>', 'tinyshield'); ?></h3>
                  <p>Toggle this to enable or disable the blocking of <a href="<?php echo esc_url('https://www.torproject.org/'); ?>'" target="_blank">Tor</a> exit nodes. Tor can be used for malicious and legitimate purposes. If you have any reason anonymous users would access your site, leave this disabled. <strong>Disabled by default.</strong></p>
                  <p><input type="checkbox" name="options[block_tor_exit_nodes]" id="options[block_tor_exit_nodes]" <?php echo ($options['block_tor_exit_nodes']) ? 'checked' : 'unchecked' ?> /> <label for="options[block_tor_exit_nodes]"><?php _e('Block Tor Exit Nodes?', 'tinyshield'); ?></label></p>

                  <h3><?php _e('Inclusive Block Countries (GeoIP Filtering) - <i>Premium Feature</i>', 'tinyshield'); ?></h3>
                  <p>Select a country or multiple countries to block from accessing your site. <strong>No countries are selected by default. Do not use in conjuction with the Exclusive Block Countries option.</strong></p>
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
                  <h3><?php _e('Exclusive Block Countries (GeoIP Filtering) - <i>Premium Feature</i>', 'tinyshield'); ?></h3>
                  <p>Select a country or multiple countries to allow access to your site assuming all countries are blocked by default. Do not use in conjuction with the Inclusive Block Countries option. <strong>Feature disabled until a country is selected.</strong></p>
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

              <?php if($options['subscription'] != 'community'): ?>
                <h3><?php _e('Cloudflare Integration - <i>Premium Feature</i>', 'tinyshield'); ?></h3>
                <p><?php _e('When enabled with valid Cloudflare credentials, when an IP is blocked it will be passed to Cloudflare (assuming your site is already setup on Cloudflare) and will blocked prior to reaching your site. This option uses the Cloudflare Challenge option rather than Block, in case of false positives. <strong>Feature disabled by default.</strong>'); ?></p>
                <p>
                  <input type="checkbox" name="options[cloudflare_enabled]" id="options[cloudflare_enabled]" <?php echo ($options['cloudflare_enabled']) ? 'checked' : 'unchecked' ?> /> <label for="options[cloudflare_enabled]"><?php _e('Enable Cloudflare Integration?', 'tinyshield'); ?></label>
                  <input size="28" type="text" placeholder="<?php _e('Cloudflare Email', 'tinyshield'); ?>" id="options[cloudflare_email]" name="options[cloudflare_email]" value="<?php (!empty($options['cloudflare_email']) ? esc_attr_e($options['cloudflare_email']) : ''); ?>" />
                  <input size="28" type="text" placeholder="<?php _e('Cloudflare Global API Key', 'tinyshield'); ?>" id="options[cloudflare_auth_key]" name="options[cloudflare_auth_key]" value="<?php (!empty($options['cloudflare_auth_key']) ? esc_attr_e($options['cloudflare_auth_key']) : ''); ?>" />
                  <input size="28" type="text" placeholder="<?php _e('Cloudflare Zone ID', 'tinyshield'); ?>" id="options[cloudflare_zone_id]" name="options[cloudflare_zone_id]" value="<?php (!empty($options['cloudflare_zone_id']) ? esc_attr_e($options['cloudflare_zone_id']) : ''); ?>" />
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
            <h3><?php _e('Blocklist', 'tinyshield'); ?></h3>
            <p><?php _e('These are addresses that have tried to visit your site and been found to be malicious. Requests from these addresses are blocked and will remain cached for 24 hours and then will be checked again.', 'tinyshield'); ?></p>
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
  }
