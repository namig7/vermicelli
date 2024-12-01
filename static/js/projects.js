// JavaScript code for projects functionality

$(document).ready(function() {
    // Variables for pagination and projects data
    let projectsData = [];
    let currentPage = 1;
    const projectsPerPage = 5;

    // Function to load projects data
    function loadProjectsData(searchQuery = '') {
        $.ajax({
            url: '/get_projects_data',
            type: 'GET',
            data: { search: searchQuery, page: currentPage },
            success: function(response) {
                projectsData = response.projects;
                displayProjects();
                updatePaginationControls(response);
            },
            error: function() {
                $('#projectListContainer').html('Error loading projects.');
            }
        });
    }

    // Other functions (displayProjects, updatePaginationControls, etc.) remain the same

    // Event handlers
    $('#searchForm').on('submit', function(e) {
        e.preventDefault();
        let searchQuery = $(this).find('input[name="search"]').val();
        loadProjectsData(searchQuery);
    });

    // Load initial data
    loadProjectsData();

    // Modal functions
    // Include your modal functions here
});
