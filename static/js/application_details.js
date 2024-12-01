// static/js/application_details.js

$(document).ready(function() {
    const currentAppId = $('#app-details').data('app-id'); // You may need to pass this variable differently

    // Function to open the edit application modal
    window.openEditAppModal = function(appId) {
        // Your code to open the edit application modal
    };

    // Function to close the edit application modal
    window.closeEditAppModal = function() {
        // Your code to close the edit application modal
    };

    // Function to save the edited application
    window.saveEditApp = function() {
        // Your code to save the application
    };

    // Function to delete the application
    window.deleteApplication = function(appId) {
        // Your code to delete the application
    };

    // Event handler for opening version history modal
    $('#openVersionHistory').on('click', function(e) {
        e.preventDefault();
        const appId = $(this).data('app-id');
        // Your code to load and display version history
    });

    // Function to copy curl command to clipboard
    window.copyToClipboard = function(elementId) {
        // Your code to copy text to clipboard
    };

    // Include other functions and event handlers as needed
    // Ensure that functions are attached to the window object if needed
    window.openEditAppModal = openEditAppModal;
    window.closeEditAppModal = closeEditAppModal;
    window.saveEditApp = saveEditApp;
    window.deleteApplication = deleteApplication;
    window.copyToClipboard = copyToClipboard;
    window.goToPage = goToPage;
});
