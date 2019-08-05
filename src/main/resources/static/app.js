$(document).ready(function () {

    let accessToken = getUrlParameter("access_token");
    if (accessToken) {
        fetch(`/v1/validate?access_token=${accessToken}`)
            .then((response) => {
                return response.json();
            })
            .then((data) => {
                Object.keys(data).forEach((key) => {
                    addTokenData("#tokenDetails",key, data[key]);
                });
            });
        fetch(`/v1/user?access_token=${accessToken}`)
            .then((response) => {
                return response.json();
            })
            .then((data) => {
                Object.keys(data).forEach((key) => {
                    addTokenData("#userDetails",key, data[key]);
                });
            });
    }

    $("#loginBtn").on("click", function () {
        window.location.href = "/v1/auth";
    });


    $("#logoutBtn").on("click", function () {
        if (accessToken){
            fetch(`/v1/logout?access_token=${accessToken}`, {method:'DELETE'})
                .then((response) => {
                    if (response.status === 200){
                        window.location.href = "/index.html";
                    }
                });
        }
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