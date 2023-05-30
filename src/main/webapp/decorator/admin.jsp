<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ include file="/common/taglib.jsp"%>
<c:url value="/view/admin/assets" var="url" />
<!DOCTYPE html>
<html lang="fr">
<head>
<!-- Site meta -->
<meta charset="UTF-8">
<meta name="viewport"
	content="width=device-width, initial-scale=1, shrink-to-fit=no">
<title>Bán nông sản</title>
<!-- CSS -->
<link href="${url}/css/pace.min.css" rel="stylesheet" />
<script src="${url}/js/pace.min.js"></script>
<link rel="stylesheet"
	href="${url}/plugins/summernote/dist/summernote-bs4.css" />
<link href="${url}/plugins/vectormap/jquery-jvectormap-2.0.2.css"
	rel="stylesheet" />
<link href="${url}/plugins/simplebar/css/simplebar.css" rel="stylesheet" />
<link href="${url}/css/bootstrap.min.css" rel="stylesheet" />
<link href="${url}/css/animate.css" rel="stylesheet" type="text/css" />
<link href="${url}/css/icons.css" rel="stylesheet" type="text/css" />
<link href="${url}/css/sidebar-menu.css" rel="stylesheet" />
<link href="${url}/css/app-style.css" rel="stylesheet" />


<!-- JS -->
<script src="${url}/js/jquery.min.js"></script>
<script src="${url}/js/popper.min.js"></script>
<script src="${url}/js/bootstrap.min.js"></script>
<script src="${url}/plugins/simplebar/js/simplebar.js"></script>
<script src="${url}/js/sidebar-menu.js"></script>
<script src="${url}/js/jquery.loading-indicator.js"></script>
<script src="${url}/js/app-script.js"></script>
<script src="${url}/plugins/Chart.js/Chart.min.js"></script>
<script src="${url}/js/index.js"></script>
<script src="${url}/plugins/summernote/dist/summernote-bs4.min.js"></script>
</head>
<body>


	<!-- header  -->

	<%@ include file="/common/admin/header.jsp"%>
	<!-- end header  -->

	<!-- 	content -->
	<dec:body />

	<!-- footer  -->
	<%@ include file="/common/admin/footer.jsp"%>
	<!-- end footer  -->
</body>
</html>