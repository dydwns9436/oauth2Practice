package com.branch.sikgu.meal.board.dto;

import com.branch.sikgu.meal.board.entity.Board;
import lombok.*;

import javax.validation.constraints.NotBlank;
import java.time.LocalDateTime;
import java.util.List;

public class BoardDto {
    @Setter
    @Getter
    @AllArgsConstructor
    @NoArgsConstructor
    public static class Post {
        @NotBlank
        private String title;
        @NotBlank
        private String body;

        private int total;
        private Board.PassedGender passedGender;
        private LocalDateTime mealTime;
        private List<String> tags;
    }

    @Getter
    @AllArgsConstructor
    @NoArgsConstructor
    @Setter
    @EqualsAndHashCode
    public static class Patch {
        @Setter
        private Long boardId;
        @NotBlank
        private String title;
        @NotBlank
        private String body;

        private int total;
        private Board.PassedGender passedGender;
        private LocalDateTime mealTime;
        private List<String> tags;
    }

    @Getter
    @AllArgsConstructor
    @Setter
    public static class Response{
        private Long memberId;
        private String nickname;
        private Long imageId;
        private Long boardId;

        private String title;
        private String body;
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;

        private int total;
        private int count;
        private Board.PassedGender passedGender;
        private LocalDateTime mealTime;
        private List<String> tags;
    }

    @Getter
    @Setter
    @AllArgsConstructor
    public static class BoardMemberResponse {
        private Long boardId;
        private String title;
        private LocalDateTime mealTime;
        private int total;
    }
}
