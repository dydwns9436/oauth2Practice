package com.branch.sikgu.meal.board.repository;

import com.branch.sikgu.meal.board.entity.Board;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface BoardRepository extends JpaRepository<Board, Long> {
    // 멤버Id와 boardId로 Board 를 찾는 건데, 필요한지 모르겠음
    Optional<Board> findByBoardIdAndMemberMemberId(Long boardId, Long memberId);

    // 게시물
    Optional<Board> findById(Long boardId);

    Board findByBoardId(Long boardId);

    // 멤버 아이디로 board 검색
    List<Board> findByMemberMemberId(Long memberId);

    // 전체 게시물 조회
    List<Board> findAll();

    // 활성화된 게시물 조회
    List<Board> findAllByBoardStatus(Board.BoardStatus boardStatus);

    // 현재 시간 이후의 게시물 조회
    List<Board> findAllByMealTimeAfterAndBoardStatus(LocalDateTime mealTime, Board.BoardStatus boardStatus);
}
