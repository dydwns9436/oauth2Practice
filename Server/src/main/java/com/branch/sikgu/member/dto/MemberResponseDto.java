package com.branch.sikgu.member.dto;

import com.branch.sikgu.image.Entity.Image;
import com.branch.sikgu.member.entity.Member;
import com.branch.sikgu.myPage.dto.MyPageResponseDto;
import com.branch.sikgu.myPage.entity.MyPage;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class MemberResponseDto {
    private Long memberId;
    private String name;
    private String email;
    private String nickname;
    private LocalDate birthday;
    private Boolean gender;
    private Member.MemberStatus status;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    public static class HistoryMemberResponse{
        private Long memberId;
        private String nickName;
    }
}