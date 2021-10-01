<?php
  class tinyShield_Dashboard extends tinyShield{

    public static function dashboard_widget(){
      if(current_user_can('manage_options')){
        wp_add_dashboard_widget(
          'tinyshield_dashboard_widget',
          esc_html__('tinyShield Overview', 'tinyshield'),
          'tinyShield_Dashboard::display_dashboard_widget'
        );
      }
    }

    public static function display_dashboard_widget(){
      $options = get_option('tinyshield_options');

      $subscriptions = array(
        'community' => __('Community', 'tinyshield'),
        'single_site' => 'Single Site',
        'five_sites' => 'Five Sites',
        'unlimited' => 'Unlimited Sites'
      );

      $news_feed = fetch_feed(self::$tinyshield_news_feed);

      ?>
        <ul>
          <?php if(!is_wp_error($news_feed)): ?>
          <li>
            <?php
              $max_feed = $news_feed->get_item_quantity(1);
              $latest_news = $news_feed->get_items(0, 1);
              $url = $latest_news[0]->get_permalink();
              $title = $latest_news[0]->get_title();
            ?>
            <h4>
              <?php _e('Latest News: ', 'tinyshield'); ?>
              <a target="_blank" href="<?php echo esc_url($url); ?>"><?php esc_html_e($title); ?></a>
            </h4>
            <hr />
          </li>
          <?php endif; ?>
          <li>
            <h4><?php _e('Your Subscription: ', 'tinyshield'); ?><strong><?php (!empty($options['subscription']) ? esc_attr_e($subscriptions[$options['subscription']]) : ''); ?></strong></h4>
            <hr />
          </li>
          <li>
            <h4><?php _e('Last 7 Days Activity - Time Zone: ', 'tinyshield'); esc_attr_e(wp_timezone_string()); ?></h4>
            <canvas id="tinyshield_dashboard_overview_chart" style="width: 100%"></canvas>
          </li>
        </ul>
      <?php
    }

  }
