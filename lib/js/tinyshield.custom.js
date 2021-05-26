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
      } else {
        $('input[name="options[cloudflare_email]"').prop('required', false);
        $('input[name="options[cloudflare_auth_key]"').prop('required', false);

        $('input[name="options[cloudflare_email]"').prop('value', '');
        $('input[name="options[cloudflare_auth_key]"').prop('value', '');
      }
    });
});
