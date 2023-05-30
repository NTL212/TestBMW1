<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri = "http://java.sun.com/jsp/jstl/core" prefix = "c" %>
<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="org.apache.commons.text.StringEscapeUtils" %>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css">
<c:url value = "/view/client/assets" var="url"/>
        <section id="menu">
    <div class="container">
      <div class="menu-area">
        <!-- Navbar -->
        <div class="navbar navbar-default" role="navigation">
          <div class="navbar-header">
            <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-collapse">
              <span class="sr-only">Toggle navigation</span>
              <span class="icon-bar"></span>
              <span class="icon-bar"></span>
              <span class="icon-bar"></span>
            </button>          
          </div>
          <div class="navbar-collapse collapse">
            <!-- Left nav -->
            <ul class="nav navbar-nav">
              <li><a class ="top-fitting" href="${pageContext.request.contextPath}/">TRANG CHỦ</a></li>
            <li><a class ="top-fitting" href="${pageContext.request.contextPath}/view/client/product">SẢN PHẨM</a>
                <ul class="dropdown-menu">                
                  <li><a href="product.jsp">RAU CỦ QUẢ</a></li>
                  <li><a href="product.jsp">CÁC LOẠI HẠT</a></li>
                  <li><a href="product.jsp">TINH DẦU</a></li>
                </ul>
              </li>
              <li class="aa-search" style="left:0;"><!-- search box -->
              <a class="aa-search-box">
                <form action="${pageContext.request.contextPath}/view/client/product/search" method="GET" onsubmit="encodeSearchInput(event)">
                  <input type="text" name="s" id="searchInput" placeholder="Tìm kiếm sản phẩm.." />
                 <button class="serach-box"><span class="fa fa-search"></span></button>
                </form>
                <script>
  				function encodeSearchInput(event) {
    				var searchInput = document.getElementById("searchInput");
   					var encodedValue = encodeURIComponent(searchInput.value); // Mã hóa giá trị nhập vào
    				searchInput.value = encodedValue; // Gán giá trị đã mã hóa lại cho input
  				}
				</script>
              </a>
              <!-- / search box -->
             </li>
              <li class="aa-cartbox">
                <a class="aa-cart-link top-fitting" style="left: 550%;" href="${pageContext.request.contextPath}/view/client/cart">
                  <span class="fas fa-cart-arrow-down"></span>
                  <span class="aa-cart-title">GIỎ HÀNG</span>
                </a>
               <c:if test="${sessionScope.username == null}">
                  <li class="hidden-xs"><a class ="top-fitting" href="${pageContext.request.contextPath}/view/client/register" style="left: 350%;">ĐĂNG KÝ</a></li>
                  <li><a class ="top-fitting" style="left: 270%;" href="${pageContext.request.contextPath}/view/client/login">ĐĂNG NHẬP</a></li>
              </c:if>
              <c:if test="${sessionScope.username != null}">
              	  <li class="nav-item nav-item-info dropdown user-dropdown">
                  <a
                    href="#"
                    class="nav-link text-white nav-item__link mb-0 top-fitting focus-user"
                    data-toggle="dropdown"
                    style="left: 170%;">
                    <i class="fa-solid fa-user icon-user"></i>                   
                    ${username}
                    <i class="fa-solid fa-sort-down icon-arrow"></i>
                  </a>
                   <div class="dropdown-menu-user left-size">
	              	  <a class ="logout-user" href="${pageContext.request.contextPath}/view/client/logout">Đăng xuất</a>
	              	</div>          
	              </li>    	 	
              </c:if>
              </li>
            </ul>
          </div><!--/.nav-collapse -->
          
        </div>
      </div>       
    </div>
  </section>
