package com.gabriela_dc.tasklist.task;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;

@Data
@Entity(name="tb_task")
public class TaskModel {

    @Id
    @GeneratedValue(generator = "UUID")
    private UUID id;

    private UUID idUser;
    private String description;

    @Column(length = 50)
    private String title;

    private LocalDateTime startAt;
    private LocalDateTime endAt;
    private String priority;

    @CreationTimestamp
    private LocalDateTime createAt;


    public void setTitle(String title) throws Exception{
        if(title.length() > 50){
            throw new Exception("O campo title deve conter no máximo 50 caracteres!");
        }
        this.title = title;
    }

}
