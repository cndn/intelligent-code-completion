var codeMirror;

var defaultSQL = `-- Welcome to the SQL Explorer
SHOW DATABASES;`;

function postQuery(query, operation) {
  $.post( "/sql", {query: query, operation: operation})

  .done(function(data) {
    response = ($.type(data) === "object")
        ? data
        : JSON.parse(data);

    console.log(response);

    if (response.error) {
      console.log("error");
      console.log(response.error);
      $('.alert #errorMessage').html("<h4>Error</h4>");
      $('.alert #errorMessage').append(response.error);
      $('.alert#alert-danger').show();
      return;
    }

    console.log(response.success)
    if (response.success == true && response.rowCount != 0) {
      $('.alert #successMessage').html("<h4>Success</h4>");
      $('.alert #successMessage').append(response.rowCount + " record(s) updated");
      $('.alert#alert-success').show();
    }

    if (!response || !response.results || response.results.length < 1) {
      return;
    }

    firstRecord = response.results[0];

    columns = [];
    if (firstRecord) {
      for (key of Object.keys(firstRecord)) {
        columns.push({"mData": key, "title": key})
      }
    }
    console.log(columns)

    $("#recordTable").empty();
    $("#recordTable").html("<table id=\"records\" class=\"table table-striped table-bordered\" cellspacing=\"0\" width=\"100%\"></table>");

    $('#records').DataTable({
      bProcessing: true,
      aaData: response.results,
      aoColumns: columns,
      lengthChange: false,
      paging: true,
      searching: true,
      dom: "<<t>fp>"
    });
  })

  .fail(function( data ) {
    console.log("FAILED");
    console.log( data );
    $('.alert #errorMessage').html("<h4>Error</h4>");
    $('.alert #errorMessage').append(response.error);
    $('.alert#alert-danger').show();
  });
};

window.onload = function() {
  $('.alert .close').click(function(e) {
      $(this).parent().hide();
  });

  $('#submit').click(function(e) {
      $('.alert').hide();

      query = codeMirror.getValue();
      operation = $('input[name=operations]:checked').attr('id');

      postQuery(query, operation);
  });

  // Set up CodeMirror
  var codeText = $("#code")[0];

  codeMirror = CodeMirror.fromTextArea(codeText, {
      mode: "text/x-mysql",
      lineNumbers: true,
      theme: "eclipse",
      lengthChange: false
  });

  codeMirror.setValue(defaultSQL);
}
