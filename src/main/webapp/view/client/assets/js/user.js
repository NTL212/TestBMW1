/**
 * 
 */
 const user = document.querySelector(".focus-user")
 const user_logout = document.querySelector(".left-size")
 
user.addEventListener('click',function focususer(){
	user_logout.classList.toggle("open");
})

