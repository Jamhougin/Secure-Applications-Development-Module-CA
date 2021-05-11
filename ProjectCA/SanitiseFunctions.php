<?php

function Sanitise($val) 
{
	
	$data = $val;
	
	$arrSearch = array('/"/', '/</', '/>/', '/#/', '/%/', '/\{/', '/\}/', '/\|/', '/\\\\/', '/\^/', '/~/', '/\[/', '/\]/', '/`/', '/=/');
	$arrReplace = array('&quot', '&lt', '&gt', '&num', '&percnt', '&lbrace', '&rbrace', '&vert', '&bsol', '&Hat', '&tilde', '&lbrack', '&rbrack', '&grave', '&#61');
	$data = preg_replace($arrSearch, $arrReplace, $data);

	return $data;
}
?>