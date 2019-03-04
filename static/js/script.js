var form = document.forms["login-form"];
var pattern = "/^\D+\w/gm";
form.onsubmit = function(){
    if (form["login"].search(/^\D+\w/gm) === -1) {
        alert("tes");
    }
}