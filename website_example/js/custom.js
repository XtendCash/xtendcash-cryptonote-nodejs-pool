/* Insert your pool's unique Javascript here */

$(function(){
    $("head").append('<link id="themeCss" type="text/css" rel="stylesheet" href="' + themeCss + '">');

	if (Cookies.get('night_mode') === '1')
	{
		changeCSS(themeCssDark, 5);
		$('.switch-checkbox').prop('checked', true);
	}
	else
	{
		changeCSS(themeCss, 5);
		$('.switch-checkbox').prop('checked', false);
	}
	$('.switch-checkbox').on('change', function() {
		setNightMode();
	});
});

function setNightMode(isSet){
	if ($('.switch-checkbox:checked').val() === 'true') {
		Cookies.set('night_mode', 1, {expires: 365});
		changeCSS(themeCssDark, 5);
	}
	else {
		Cookies.set('night_mode', 0, {expires: 365});
		changeCSS(themeCss, 5);
	}
}

function changeCSS(cssFile, cssLinkIndex) {

    var oldlink = document.getElementsByTagName("link").item(cssLinkIndex);

    var newlink = document.createElement("link");
    newlink.setAttribute("rel", "stylesheet");
    newlink.setAttribute("type", "text/css");
    newlink.setAttribute("href", cssFile);

    document.getElementsByTagName("head").item(0).replaceChild(newlink, oldlink);
}
