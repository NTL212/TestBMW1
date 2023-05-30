<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri = "http://java.sun.com/jsp/jstl/core" prefix = "c" %>
<c:url value = "/view/admin/assets" var="url"/>
    <div id="sidebar-wrapper" data-simplebar="" data-simplebar-auto-hide="true">
      <div class="brand-logo">
        <a href="${pageContext.request.contextPath}/admin/homepage">
          <h5 class="logo-text text-center">ADMIN</h5>
        </a>
      </div>
      <ul class="sidebar-menu do-nicescrol">
        <li class="sidebar-header">MENU ADMIN</li>
         <li>
          <a href="${pageContext.request.contextPath}/admin/admin/list">
            <i class="zmdi zmdi-account-box"></i> <span>Quản lí Admin</span>
          </a>
        </li>
        <li>
          <a href="${pageContext.request.contextPath}/admin/user/list">
            <i class="zmdi zmdi-accounts"></i> <span>Quản lí User</span>
          </a>
        </li>
        <li>
          <a href="${pageContext.request.contextPath}/admin/category/list">
            <i class="zmdi zmdi-grid"></i> <span>Chuyên Mục</span>
          </a>
        </li>
        <li>
          <a href="${pageContext.request.contextPath}/admin/product/list">
            <i class="zmdi zmdi-widgets"></i> <span>Danh Sách Sản Phẩm</span>
          </a>
        </li>
        <li>
          <a href="${pageContext.request.contextPath}/admin/order/list">
            <i class="zmdi zmdi-shopping-cart"></i> <span>Đơn Hàng</span>
          </a>
        </li>
        
        <li>
          <a href="${pageContext.request.contextPath}/admin/order/list-detail">
            <i class="zmdi zmdi-shopping-cart"></i> <span>Chi Tiết Đơn Hàng</span>
          </a>
        </li>
      </ul>
    </div>