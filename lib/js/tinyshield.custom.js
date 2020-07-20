jQuery(document).ready(function($){
    $('.country-select-block').select2({
      placeholder: "Which Countries Would You Like To Block?"
    });

    $('.country-select-allow').select2({
      placeholder: "Which Countries Would You Like To Allow?"
    });
});
