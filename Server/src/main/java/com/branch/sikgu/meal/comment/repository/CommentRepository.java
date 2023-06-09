package com.branch.sikgu.meal.comment.repository;

import com.branch.sikgu.meal.comment.entity.Comment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface CommentRepository extends JpaRepository<Comment, Long> {
    // 해당 게시물에서 댓글 가져오기
    @Query(value = "SELECT c FROM Comment c WHERE c.schedule.boardId = :boardId")
    List<Comment> findByBoardId (long boardId);

    // 해당 멤버가 작성한 댓글 가져오기
//    @Query(value = "SELECT c FROM Comment c WHERE c.member.memberId = :memberId")
//    List<Comment> findByMemberId (long memberId);
}
