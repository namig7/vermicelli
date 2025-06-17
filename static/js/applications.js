// JavaScript code for applications functionality

$(document).ready(function() {
    // Variables for pagination and applications data
    let appsData = [];
    let currentPage = 1;
    const appsPerPage = 5;

    // Function to load applications data
    function loadAppsData(searchQuery = '') {
        $.ajax({
            url: '/get_applications_data',
            type: 'GET',
            data: { search: searchQuery },
            success: function(data) {
                appsData = data;
                currentPage = 1; // Reset to first page on new search
                displayApps(currentPage);
                updatePaginationControls();
            },
            error: function() {
                $('#appListContainer').html('Error loading applications.');
            }
        });
    }

    // Other functions (displayApps, updatePaginationControls, etc.) remain the same

    // Event handlers
    // Ensure event handlers are set up after content is loaded
    $('#searchForm').on('submit', function(e) {
        e.preventDefault();
        let searchQuery = $(this).find('input[name="search"]').val();
        loadAppsData(searchQuery);
    });

    // Load initial data
    loadAppsData();

    // Modal functions
    // Include your modal functions here
});

// Attach event handler for application name link
$('#appListContainer').on('click', '.app-details-link', function(e) {
    e.preventDefault();
    const appId = $(this).data('id');
    window.loadPage('application_details', appId);
});