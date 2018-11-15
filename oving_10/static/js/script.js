function getProtectedResource() {
    /*
      Henter en beskyttet ressurs ved å bruke access-tokenen klienten fikk ved innlogging.
    */
    $.ajax({
        url: "/protected-resource",
        headers: {
            Authorization: "Bearer " + window.localStorage.getItem("token")
        }
    })
    .done(function (response) {
        $("#response").show().find(".card-body").text("Serveren svarer: " + response);
    })
    .fail(function (xhr) {
        $("#response").show().find(".card-body").text("Serveren svarer: " + xhr.responseText);
    });
}

$(function () {
    $("#btn_login").click(function() {
        $("#response").hide();

        let username = $("#username").val();
        let password = $("#password").val();
        /*
          Hasher passordet på klientsiden før det sendes til serveren.
          Brukernavnet brukes som salt, siden det er unikt for brukeren og alltid tilgjengelig.
          Hasher med få iterasjoner siden dette er en treng operasjon i javascript,
          og vi vil unngå å la brukeren vente for lenge.
        */
        let hash = CryptoJS.PBKDF2(password, username, {iterations: 100, keySize: 8}).toString();

        $.ajax({
            url: "/authenticate",
            method: "POST",
            data: JSON.stringify({
                "username": username,
                "password": hash
            }),
            contentType: "application/json"
        })
        .done(function (response) {
            if (response.success) {
                window.localStorage.setItem("token", response.token);
                getProtectedResource();
            }
        })
        .fail(function (xhr) {
            let response = JSON.parse(xhr.responseText);
            if (!response.success) {
                $("#wrong_credentials_response").slideDown().delay(5000).slideUp();
            }
        });
    });
});
