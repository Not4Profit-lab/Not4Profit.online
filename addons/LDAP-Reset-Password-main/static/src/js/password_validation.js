var timeout;

$("#new_password").on('keyup', function() {
    var password = $(this).val();
    var result = zxcvbn(password);
    var strengthDiv = $("#password_strength");

    // Update the password strength visualization
    if (result.score === 0) {
        strengthDiv.removeClass().addClass('strength weak');
    } else if (result.score === 2) {
        strengthDiv.removeClass().addClass('strength medium');
    } else if (result.score >= 3) {
        strengthDiv.removeClass().addClass('strength strong');
    }

    clearTimeout(timeout);
    timeout = setTimeout(function() {

        var json_data = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {
                "password": password
            },
            "id": new Date().getTime()
        };
        $.ajax({
            url: '/validate_password',
            type: 'POST',
            data: JSON.stringify(json_data),
            contentType: "application/json; charset=utf-8",
            dataType: "json",
            success: function(response) {
                if (response.error) {
                    $("#error_message").text(response.error);
                }
                else if (response.result && response.result.hasOwnProperty('valid')) { // Check if result and valid
                    if (response.result.valid) {
                        $("#password_error").text("");
                    } 
                    else {
                        // If there's an error from frontend, display it
                        $("#password_error").text(response.result.message); // Access message from response.result
                    }
                } 
                else {
                    console.error("Unexpected response from server:", response);
                }
            }
        });
    }, 300);
});

$("#confirm_password").on('keyup', function() {
    var newPassword = $("#new_password").val();
    var confirmPassword = $(this).val();

    if (newPassword !== confirmPassword) {
        $("#confirm_password_error").text("Passwords do not match!");
    } else {
        $("#confirm_password_error").text("");
    }
});
