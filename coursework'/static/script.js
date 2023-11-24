document.getElementById('themeToggle').addEventListener('change', function(event){
    if (event.target.checked) {
        document.body.style.backgroundColor = "black";
        document.body.style.color = "white";
    } else {
        document.body.style.backgroundColor = "#f4f4f4";
        document.body.style.color = "black";
    }
});
