var codeInput;
var codeOutput;

var defaultPython = `# Welcome to the Python Explorer
import random;

firstRandom = random.randint(1, 100);
secondRandom = random.randint(1, 100);

sum = firstRandom + secondRandom;

print ("The first random number is: " + str(firstRandom));
print ("The second random number is: " + str(secondRandom));

print ("The sum of the random numbers is: " + str(sum));
`;

function postQuery(code) {
  $.post( "/python", {code: code})

  .done(function(data) {
    response = ($.type(data) === "object")
          ? data
          : JSON.parse(data);

    codeOutput.setValue(response.stdout);
    console.log(codeOutput);

    console.log(response);

    if (response.stderr) {
      console.log("SHOWING ERR " + response.stderr)
      $('.alert #errorMessage').html("<h4>Error</h4>");
      $('.alert #errorMessage').append(response.stderr);
      $('.alert#alert-danger').show();
    }
  })

  .fail(function( data ) {
    console.log("FAILED");
    console.log( data );
     $('.alert #errorMessage').html("<br>" + data.status + " " + data.statusText)
     $('.alert#alert-danger').show()
  });
};

window.onload = function() {
  $('.alert .close').click(function(e) {
      $(this).parent().hide()
  });

  $('#submit').click(function(e) {
      $('.alert').hide();
      code = codeInput.getValue();
      postQuery(code);
  });

  // Set up CodeMirror
  var codeInputText = $("#code")[0];
  var codeOutputText = $("#output")[0];

  codeInput = CodeMirror.fromTextArea(codeInputText, {
      mode: "python",
      lineNumbers: true,
      theme: "eclipse"
  });

  codeOutput = CodeMirror.fromTextArea(codeOutputText, {
      mode: "x-sh",
      lineNumbers: true,
      theme: "eclipse",
      readOnly: true
  });

  codeInput.setValue(defaultPython);
}
