
function getLobyList(mu_type, target) {

	logind = $("input[name=userid]").length == 0;

	$.ajax({
		url : "/json/swix.asp",
		 dataType: "json",
		data : {
			mode : "lobby",
			mu_type : mu_type
		},
		success : function(data) {

			lobys = data.lists;


			html = '';
			if (logind && data.swix_change_type == '1') {
				html += '<button type="button" class="btn_point_change ui-button_red">포인트전환</button>';
			}
			template = $('.'+ target).html();
			for (i = 0; i < lobys.length; i++) {
				loby = lobys[i];
				result = template;
				for (key in loby) {
					result = result.replaceAll('[['+key+']]', loby[key]);
				}
				html += result;
			}
			$('.'+ target).html(html);
			

			$('.btn_point_change').click(function() {
				$.ajax({
					url : "/json/getMemberInfoJson.asp",
					success : function(data) {
						$(".sports_point").text(data);
					}
				});

				$.ajax({
					url : "/swix.asp?mode=get_point",
					success : function(data) {
						if (data.indexOf('script') > 0) {
							data = /alert\('([^']+)'\)/.exec(data)[1];
							alert(data);
						} else {
							$(".casino_point").text(data);
						}
					}
				});

				$('.point_change').show();
				$('.ly002').show();
			});

			$('#ly003-close').click(function(e) {
				e.preventDefault();
				$('.point_change').hide();
				$('.ly002').hide();
			}).css('cursor', 'pointer');

			$.each($("input.money"), function() {
				$(this).keyup(function() {
					$(this).val($(this).val().replace(/,/gi,'').money())
				});
			});

			$('#w_from').change(function() {
				if ($(this).val() == '04' &&  $('#w_to option:selected').val()  == '04' ) {
					$("#w_to").val("01").prop("selected", true);
				}
				if ($(this).val() == '01' &&  $('#w_to option:selected').val()  == '01' ) {
					$("#w_to").val("04").prop("selected", true);
				}
			});

			$('#w_to').change(function() {
				if ($(this).val() == '04' &&  $('#w_from option:selected').val()  == '04' ) {
					$("#w_from").val("01").prop("selected", true);
				}
				if ($(this).val() == '01' &&  $('#w_from option:selected').val()  == '01' ) {
					$("#w_from").val("04").prop("selected", true);
				}
			});

			statusment = false;

			$('#btnMoneyAct').off().on('click', function() {

				if (statusment) {
					alert("처리진행중입니다.\n\n잠시만 기다려 주세요.");
					return false;
				}
				amount = parseInt($('#amount').val().replace(/\,/gi, ""),10);
				sports_point = parseInt($(".sports_point").text().replace(/\,/gi, ""),10);
				casino_point = parseInt($(".casino_point").text().replace(/\,/gi, ""),10);

				w_to = $('#w_to').val();

				if (! amount || amount == 0) {
					alert("전환하실 포인트를 입력해 주세요.");
					$("#amount").get(0).focus();
					return false;
				}

				if (!$("#amount").val().isNum(',')) {
					alert("숫자만 입력가능합니다.");
					$("#amount").val('').get(0).focus();
					return false;
				}

				if (w_to == '01') {
					if (amount > casino_point) {
						alert("전환하실 포인트가 부족합니다.");
						$("#amount").focus();
						return false;
					}
				}

				if (w_to == '04') {
					if (amount > sports_point) {
						alert("전환하실 포인트가 부족합니다.");
						$("#amount").focus();
						return false;
					}
				}

				statusment = true;

				mu_type = $('.toggle_section.active').find('.companys-title').eq(0).data('mutype') || mu_type;

				$.ajax({
					url : "/swix.asp",
					data : {
							mode : "change",
							w_to :w_to,
							amount : amount,
							mu_type : mu_type
						},
					success : function(data) {
						if (data.indexOf('script') > 0) {
							data = /alert\('([^']+)'\)/.exec(data)[1];
							alert(data);
						}
						statusment = false;
					},
					error : function(request, status, error) {
						if (status != "" && error != "") {
							alert('처리중 오류가 발생했습니다.\n\n문제가 지속될 경우 관리자에게 문의해주세요.');
						}
						location.reload()
					}
				});
			});

			$('.companys-title, .pragmatic_event').click(function() {
				thirdpartycode = $(this).data('thirdpartycode');
				gamecode = $(this).data('gamecode');
				mutype = $(this).data('mutype');

				if (mutype == 9) {
					if (logind == false) {
						$(".modal").fadeIn();
					} else {
						var objPopup=window.open('about:blank','','');
						objPopup.location.href= "/swix.asp?mode=open&thirdpartycode="+thirdpartycode+"&gamecode="+gamecode+"&mu_type="+mutype;

						if (data.swix_change_type == '2') {
							setInterval(function() {
								getCasinoPoint();
								setMemberPoint();
							}, 5000);
						}
					}

					$(".modal-close").click(function(){
						$(".modal").fadeOut();
					});

				} else if (mutype == 10) {
					$.ajax({
						url : "/json/swix.asp",
						 dataType: "json",
						data : {
							mode : "gamelist_json",
							thirdpartycode : thirdpartycode
						},
						success : function(data) {

							games = data.data.list;

							var disables;

							$.ajax({
								url : "/json/swix.asp",
								dataType: "json",
								async:false,
								data : {
									mode : "getDisableSlot"
								},
								success : function(data) {
									disables = data.lists;
								},
								error : function(request, status, error) {
									if (status != "" && error != "") {
										alert('처리중 오류가 발생했습니다.\n\n문제가 지속될 경우 관리자에게 문의해주세요.');
									}
									statusment = false;
								}
							});

							displayList(games, disables);

							$('#slot_search').on('input', function () {
								var searchTerm = $(this).val().toLowerCase();
								var filteredGames = filterGames(games, disables, searchTerm);
								displayList(filteredGames, disables);
							});
							
							$('#slot-game').show();
							$('.slot-game-layer').slideDown(500);

							$(".modal-close").click(function(){
								$(".modal").fadeOut();
							});
						},
						error : function(request, status, error) {
							if (status != "" && error != "") {
								alert('처리중 오류가 발생했습니다.\n\n문제가 지속될 경우 관리자에게 문의해주세요.');
							}
							statusment = false;
						}
					});
				}
			});
		},
		error : function(request, status, error) {
			if (status != "" && error != "") {
				alert('처리중 오류가 발생했습니다.\n\n문제가 지속될 경우 관리자에게 문의해주세요.');
			}
			statusment = false;
		}
	});
}

function displayList(games, disables) {
	html = '';
	for (i = 0; i < games.length; i++) {
		game = games[i];

		if (disables.includes(game.code) == false) {
			html += '<li data-gamecode="'+game.code+'">';
			html += '	<img src="'+game.img_1+'" >';
			html += '	<span>'+game.name_kor+'</sapn>';
			html += '</li>';
		}
	}
	$('#slot-game-list').html(html).find("li").off().on("click", function() {
		if (logind == false) {
			$('#close-slot-game').trigger("click");
			$(".modal").fadeIn();
		} else {
			gamecode = $(this).data('gamecode');
			var objPopup=window.open('about:blank','','');
			objPopup.location.href= "/swix.asp?mode=open&thirdpartycode="+thirdpartycode+"&gamecode="+gamecode+"&mu_type="+$(this).data('mutype');
		}
	});      
}

function filterGames(games, disables, searchTerm) {
	return games.filter(function (game) {
		return game.name_kor.toLowerCase().includes(searchTerm) && !disables.includes(game.code);
	});
}


$('#close-slot-game').click(function() {
	$('.slot-game-layer').slideUp();
	$('#slot-game').hide();
});


function getSlotView() {
	$.ajax({
		url : "/lobby_json.asp",
		dataType: "json",
		data : {
			view : "gamelist_json",
			thirdpartycode : thirdpartycode
		},
		success : function(data) {
			if (data.result == 0 ) {
				alert(data.msg);
				return false;
			}

			games = data.data.list;

			var disables;

			$.ajax({
				url : "/lobby_json.asp",
				dataType: "json",
				async:false,
				data : {
					view : "getDisableSlot"
				},
				success : function(data) {
				
					disables = data.lists;
				},
				error : function(request, status, error) {
					if (status != "" && error != "") {
						alert('처리중 오류가 발생했습니다.\n\n문제가 지속될 경우 관리자에게 문의해주세요.');
					}
					statusment = false;
				}
			});

			html = '';
			for (i = 0; i < games.length; i++) {
				game = games[i];

				if (disables.includes(game.code) == false) {
					html += '<li>';
					html += '<div class="companys-title code'+thirdpartycode+' hvr-wobble-vertical';
					html += '	hvr-outline-in login-modal" data-thirdpartycode="'+thirdpartycode+'" data-gamecode="'+game.code+'">';
					html += '	<img src="'+game.img_1+'" class="slot_list" data-thirdpartycode="'+thirdpartycode+'" data-gamecode="'+game.code+'">';
					html += '	<span>'+game.name_kor+'</sapn>';
					html += '	</div>';
					html += '</li>';
				}
			}
			$('.submenu').append(html);

			$(".login-modal").click(function(){
				$(".modal").fadeIn();
			});

			$(".modal-close").click(function(){
				$(".modal").fadeOut();
			});
		},
		error : function(request, status, error) {
			if (status != "" && error != "") {
				alert('처리중 오류가 발생했습니다.\n\n문제가 지속될 경우 관리자에게 문의해주세요.');
			}
			statusment = false;
		}
	});
}

$(document).ready(function(){
	logind = $("input[name=userid]").length == 0;
	$(".companys-title3").click(function(e){
		e.preventDefault();
		if(logind) {
			location.href = "game_list.asp?bt_type=" + $(this).data("type");
		} else {
			$(".modal").fadeIn();
		}
	});
});
