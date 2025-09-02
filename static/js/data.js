$(document).ready(function() {
    // Uploaded Table
    $('#uploadedTable').DataTable({
        fixedHeader: true,
        scrollX: true,
        scrollY: '270px',
        scrollCollapse: true,
        paging: true,
        pageLength: 10,
        lengthMenu: [[5, 10, 15, 20], [5, 10, 15, 20]],
        order: [[2, "desc"]],
        dom: '<"row align-items-center mb-3"<"col-sm-3"l><"col-sm-6 text-center"r><"col-sm-3"f>><"row"<"col-sm-12"t>><"row mt-3"<"col-sm-6"i><"col-sm-6 text-end"p>>'
    });

    $('.dataTables_wrapper .dataTables_length').parent().next('.text-center')
        .html('<div class="fw-bold fs-5">📜 Your Uploaded Records</div>');

    // Grouped Table
    $('#groupedTable').DataTable({
        paging: true,
        scrollY: '120px',
        pageLength: 5,
        lengthMenu: [5, 10, 20, 50],
        searching: true,
        ordering: true,
        order: [[2, 'desc']],
        dom: '<"d-flex justify-content-between align-items-center mb-3"<"dataTables_length"l><"recent-title text-center flex-grow-1"><"dataTables_filter"f>>tip',
        initComplete: function () {
            $("div.recent-title").html('<h5 class="mb-0">📝 Recent Uploads</h5>');
        }
    });

    // Project Dropdown
    $('#projectDropdown').select2({
        placeholder: "Search or select a project",
        allowClear: true,
        width: '100%'
    });

    $('#projectDropdown').on('change', function () {
        const selectedProject = $(this).val();
        const currentUrl = new URL(window.location.href);
        currentUrl.searchParams.set('project_name', selectedProject || '');
        window.location.href = currentUrl.toString();
    });
});
