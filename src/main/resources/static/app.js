$(document).ready(function () {

    let accessToken = getUrlParameter("access_token");
    if (accessToken) {
        console.log(`http://127.0.0.1:8080/v1/validate?access_token=${accessToken}`)
        fetch(`/v1/validate?access_token=${accessToken}`)
            .then((response) => {
            return response.json();
    }).
        then((data) => {
            Object.keys(data).forEach((key) => {
                // if (key === 'claims'){
                //     Object.keys(data[key]).forEach((claimKey)=>{
                //         addTokenData("#tokenDetails",claimKey, data[key][claimKey])
                //     })
                // }
                // else{
                    addTokenData("#tokenDetails",key, data[key])
                // }
            });
        });
    }

    $("#loginBtn").on("click", function () {
        window.location.href = "/v1/auth";
    });
});

function addTokenData(destDiv, key, value){
    let elem = `<div div class="row"> <div class="col-4"> ${key} </div> <div class="col-8"> ${value} </div> </div>`
    $( destDiv ).append( elem );
}

var getUrlParameter = function getUrlParameter(sParam) {
    var sPageURL = window.location.search.substring(1),
        sURLVariables = sPageURL.split('&'),
        sParameterName,
        i;

    for (i = 0; i < sURLVariables.length; i++) {
        sParameterName = sURLVariables[i].split('=');

        if (sParameterName[0] === sParam) {
            return sParameterName[1] === undefined ? true : decodeURIComponent(sParameterName[1]);
        }
    }
};