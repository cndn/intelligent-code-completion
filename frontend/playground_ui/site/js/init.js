  var cm;

  function postQuery(query, operation) {
    $.post( "/sql", {query: query, operation: operation})

    .done(function(data) {
      console.log(data);
      response = JSON.parse(data)
      console.log(response.results);

      if (response.error) {
        console.log("error");
        console.log(response.error);
        $('.alert #errorMessage').html("<h4>Error</h4>");
        $('.alert #errorMessage').append(response.error);
        $('.alert').show();
        return;
      }

      if (response.success == true && response.rowCount != 0) {
        $('.alert #successMessage').html("<h4>Sucess</h4>");
        $('.alert #successMessage').append(response.rowCount + " record(s) updated");
        $('#success').show();
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
        "bProcessing": true,
        "aaData": response.results,
        "aoColumns": columns
      });
    })

    .fail(function( data ) {
      console.log("FAILED");
      console.log( data );
       $('.alert #message').append("<br>" + data.status + " " + data.statusText)
       $('.alert').show()
    });
  };

window.onload = function() {
  $("#code").val("SHOW DATABASES;");

  $('.alert .close').click(function(e) {
      console.log("hide alert")
      $(this).parent().hide()
  });

  $('#submit').click(function(e) {
      $('.alert').hide();
      query = cm.getValue();
      operation = $('input[name=operations]:checked').attr('id')

      console.log("run query " + query + " " + operation)

      postQuery(query, operation)
  });

  // Set up CodeMirror
  var codeText = $("#code")[0];

  cm = CodeMirror.fromTextArea(codeText, {
      mode: "sql",
      lineNumbers: true,
      theme: "eclipse"
  })
}
