$(document).ready(function () {

  // USERS TABLE
  const usersTable = $('#usersTable').DataTable({
    fixedHeader: true,
    scrollY: '360px',
    scrollCollapse: true,
    paging: true,
    pageLength: 10,
    lengthMenu: [
      [5, 10, 15, 20],
      [5, 10, 15, 20]
    ],
    stateSave: false,
    ordering: true,
    bLengthChange: true,
    bFilter: true,
    info: true,
    pagingType: "simple_numbers",
    order: [
      [2, "desc"]
    ],
    dom:
      '<"row align-items-center mb-3"' +
      '<"col-sm-3"l>' +
      '<"col-sm-6 text-center"r>' +
      '<"col-sm-3 text-end"f>' +
      '>' +
      '<"row"<"col-sm-12"t>>' +
      '<"row mt-3"<"col-sm-6"i><"col-sm-6 text-end"p>>'
  });

  // Add custom title for Users Table
  $('#usersTable_wrapper .dataTables_length')
    .parent()
    .next('.text-center')
    .html('<div class="fw-bold fs-5">👥 Existing Users</div>');

  // PROJECTS TABLE (same config as USERS TABLE)
  const projectsTable = $('#projectsTable').DataTable({
    fixedHeader: true,
    scrollY: '360px',
    scrollCollapse: true,
    paging: true,
    pageLength: 10,
    lengthMenu: [
      [5, 10, 15, 20],
      [5, 10, 15, 20]
    ],
    stateSave: false,
    ordering: true,
    bLengthChange: true,
    bFilter: true,
    info: true,
    pagingType: "simple_numbers",
    order: [
      [0, "asc"]
    ],
    dom:
      '<"row align-items-center mb-3"' +
      '<"col-sm-3"l>' +
      '<"col-sm-6 text-center"r>' +
      '<"col-sm-3 text-end"f>' +
      '>' +
      '<"row"<"col-sm-12"t>>' +
      '<"row mt-3"<"col-sm-6"i><"col-sm-6 text-end"p>>'
  });

  // Add custom title for Projects Table
  $('#projectsTable_wrapper .dataTables_length')
    .parent()
    .next('.text-center')
    .html('<div class="fw-bold fs-5">📂 Existing Projects</div>');

});

// Delete confirmation modal for Users
function confirmDelete(username) {
  const modal = new bootstrap.Modal(document.getElementById('deleteModal'));
  document.getElementById('deleteUsername').value = username;
  document.getElementById('modalUsername').innerText = username;
  modal.show();
}
