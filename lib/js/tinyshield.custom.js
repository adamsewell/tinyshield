jQuery(document).ready(function($){

    //apply select2 to geoip blocking
    $('.country-select-block').select2({
      placeholder: "Which Countries Would You Like To Block?"
    });

    //apply select2 to geoip blocking
    $('.country-select-allow').select2({
      placeholder: "Which Countries Would You Like To Allow?"
    });

    //require the email and api key for cloudflare if trying to enable
    $('input[name="options[cloudflare_enabled]"]').click(function(){
      if ($('input[name="options[cloudflare_enabled]"]').is(':checked')){
        $('input[name="options[cloudflare_email]"').prop('required', true);
        $('input[name="options[cloudflare_auth_key]"').prop('required', true);
        $('input[name="options[cloudflare_zone_id]"').prop('required', true);
      } else {
        $('input[name="options[cloudflare_email]"').prop('required', false);
        $('input[name="options[cloudflare_auth_key]"').prop('required', false);
        $('input[name="options[cloudflare_zone_id]"').prop('required', false);

        $('input[name="options[cloudflare_email]"').prop('value', '');
        $('input[name="options[cloudflare_auth_key]"').prop('value', '');
        $('input[name="options[cloudflare_zone_id]"').prop('value', '');
      }
    });

    const tinyshield_dashboard_data = {
      labels: tinyshield.labels,
      datasets: [{
        label: 'Blocked Requests',
        backgroundColor: 'rgba(255, 99, 71, 0.5)',
        borderColor: 'rgba(255, 99, 71)',
        data: tinyshield.data.blocked,
      },
      {
        label: 'Allowed Requests',
        backgroundColor: 'rgba(58, 94, 205, 0.5)',
        borderColor: 'rgba(58, 94, 205)',
        data: tinyshield.data.allowed,
      }]
    };

    const tinysheild_dashboard_chart_cfg = {
      type: 'line',
      data: tinyshield_dashboard_data,
      options: {
        responsive: true,
      },
    };

    if($('#tinyshield_dashboard_overview_chart').length){
      var tinysheild_dashboard_chart = new Chart($('#tinyshield_dashboard_overview_chart'),
        tinysheild_dashboard_chart_cfg
      );
    }
});
