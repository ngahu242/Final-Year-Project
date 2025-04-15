document.addEventListener('DOMContentLoaded', function() {
    // Update hidden input when tabs change
    const tabs = document.querySelectorAll('#inputTypeTabs .nav-link');
    const inputTypeField = document.getElementById('input_type');

    tabs.forEach(tab => {
        tab.addEventListener('click', function() {
            const type = this.id.split('-')[0];
            inputTypeField.value = type;

            // Clear all textareas/inputs when switching tabs
            document.querySelectorAll('textarea, input[type="url"]').forEach(el => {
                el.value = '';
            });
        });
    });

    // Form validation
    const form = document.querySelector('form');
    form.addEventListener('submit', function(e) {
        const activeTab = document.querySelector('.tab-pane.active');
        const input = activeTab.querySelector('textarea, input[type="url"]');

        if (!input.value.trim()) {
            e.preventDefault();
            alert(`Please enter ${inputTypeField.value} content to analyze.`);
            input.focus();
        }
    });
});
